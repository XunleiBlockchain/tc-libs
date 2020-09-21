package bal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"unicode"
)

var cdc = NewCodec()

var (
	jsonMarshalerType   = reflect.TypeOf(new(json.Marshaler)).Elem()
	jsonUnmarshalerType = reflect.TypeOf(new(json.Unmarshaler)).Elem()
	errorType           = reflect.TypeOf(new(error)).Elem()
)

//----------------------------------------
// PrefixBytes/DisambBytes/DisfixBytes types

// Lengths
const (
	PrefixBytesLen = 4
	DisambBytesLen = 3
	DisfixBytesLen = PrefixBytesLen + DisambBytesLen
)

// Prefix types
type (
	PrefixBytes [PrefixBytesLen]byte
	DisambBytes [DisambBytesLen]byte
	DisfixBytes [DisfixBytesLen]byte // Disamb+Prefix
)

// Copy into PrefixBytes
func NewPrefixBytes(prefixBytes []byte) PrefixBytes {
	pb := PrefixBytes{}
	copy(pb[:], prefixBytes)
	return pb
}

func (pb PrefixBytes) Bytes() []byte             { return pb[:] }
func (pb PrefixBytes) EqualBytes(bz []byte) bool { return bytes.Equal(pb[:], bz) }
func (db DisambBytes) Bytes() []byte             { return db[:] }
func (db DisambBytes) EqualBytes(bz []byte) bool { return bytes.Equal(db[:], bz) }
func (df DisfixBytes) Bytes() []byte             { return df[:] }
func (df DisfixBytes) EqualBytes(bz []byte) bool { return bytes.Equal(df[:], bz) }

// Return the DisambBytes and the PrefixBytes for a given name.
func NameToDisfix(name string) (db DisambBytes, pb PrefixBytes) {
	return nameToDisfix(name)
}

//----------------------------------------
// Codec internals

type TypeInfo struct {
	Type      reflect.Type // Interface type.
	PtrToType reflect.Type
	ZeroValue reflect.Value
	ZeroProto interface{}
	InterfaceInfo
	ConcreteInfo
	StructInfo
}

type InterfaceInfo struct {
	Priority     []DisfixBytes               // Disfix priority.
	Implementers map[PrefixBytes][]*TypeInfo // Mutated over time.
	InterfaceOptions
}

type InterfaceOptions struct {
	Priority           []string // Disamb priority.
	AlwaysDisambiguate bool     // If true, include disamb for all types.
}

type ConcreteInfo struct {

	// These fields are only set when registered (as implementing an interface).
	Registered       bool // Registered with RegisterConcrete().
	PointerPreferred bool // Deserialize to pointer type if possible.
	// NilPreferred     bool        // Deserialize to nil for empty structs if PointerPreferred.
	Name            string      // Registered name.
	Disamb          DisambBytes // Disambiguation bytes derived from name.
	Prefix          PrefixBytes // Prefix bytes derived from name.
	ConcreteOptions             // Registration options.

	// These fields get set for all concrete types,
	// even those not manually registered (e.g. are never interface values).
	IsAminoMarshaler       bool         // Implements MarshalAmino() (<ReprObject>, error).
	AminoMarshalReprType   reflect.Type // <ReprType>
	IsAminoUnmarshaler     bool         // Implements UnmarshalAmino(<ReprObject>) (error).
	AminoUnmarshalReprType reflect.Type // <ReprType>
}

type StructInfo struct {
	Fields []FieldInfo // If a struct.
}

func (cinfo ConcreteInfo) GetDisfix() DisfixBytes {
	return toDisfix(cinfo.Disamb, cinfo.Prefix)
}

type ConcreteOptions struct {
}

type FieldInfo struct {
	Name         string        // Struct field name
	Type         reflect.Type  // Struct field type
	Index        int           // Struct field index
	ZeroValue    reflect.Value // Could be nil pointer unlike TypeInfo.ZeroValue.
	UnpackedList bool          // True iff this field should be encoded as an unpacked list.
	FieldOptions               // Encoding options
}

type FieldOptions struct {
	JSONName      string // (JSON) field name
	JSONOmitEmpty bool   // (JSON) omitempty
	BinFixed64    bool   // (Binary) Encode as fixed64
	BinFixed32    bool   // (Binary) Encode as fixed32
	BinFieldNum   uint32 // (Binary) max 1<<29-1
	Unsafe        bool   // e.g. if this field is a float.
}

//----------------------------------------
// Codec

type Codec struct {
	mtx              sync.RWMutex
	sealed           bool
	typeInfos        map[reflect.Type]*TypeInfo
	interfaceInfos   []*TypeInfo
	concreteInfos    []*TypeInfo
	disfixToTypeInfo map[DisfixBytes]*TypeInfo
	nameToTypeInfo   map[string]*TypeInfo
}

func NewCodec() *Codec {
	cdc := &Codec{
		sealed:           false,
		typeInfos:        make(map[reflect.Type]*TypeInfo),
		disfixToTypeInfo: make(map[DisfixBytes]*TypeInfo),
		nameToTypeInfo:   make(map[string]*TypeInfo),
	}
	return cdc
}

func getTypeFromPointer(ptr interface{}) reflect.Type {
	rt := reflect.TypeOf(ptr)
	if rt.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("expected pointer, got %v", rt))
	}
	return rt.Elem()
}

// This function should be used to register all interfaces that will be
// encoded/decoded by go-amino.
// Usage:
// `amino.RegisterInterface((*MyInterface1)(nil), nil)`
func (cdc *Codec) RegisterInterface(ptr interface{}, iopts *InterfaceOptions) {
	cdc.assertNotSealed()

	// Get reflect.Type from ptr.
	rt := getTypeFromPointer(ptr)
	if rt.Kind() != reflect.Interface {
		panic(fmt.Sprintf("RegisterInterface expects an interface, got %v", rt))
	}

	// Construct InterfaceInfo
	var info = cdc.newTypeInfoFromInterfaceType(rt, iopts)

	// Finally, check conflicts and register.
	func() {
		cdc.mtx.Lock()
		defer cdc.mtx.Unlock()

		cdc.collectImplementersNolock(info)
		err := cdc.checkConflictsInPrioNolock(info)
		if err != nil {
			panic(err)
		}
		cdc.setTypeInfoNoLock(info)
	}()
	/*
		NOTE: The above func block is a defensive pattern.

		First of all, the defer call is necessary to recover from panics,
		otherwise the Codec would become unusable after a single panic.

		This “defer-panic-unlock” pattern requires a func block to denote the
		boundary outside of which the defer call is guaranteed to have been
		called.  In other words, using any other form of curly braces (e.g.  in
		the form of a conditional or looping block) won't actually unlock when
		it might appear to visually.  Consider:

		```
		var info = ...
		{
			cdc.mtx.Lock()
			defer cdc.mtx.Unlock()

			...
		}
		// Here, cdc.mtx.Unlock() hasn't been called yet.
		```

		So, while the above code could be simplified, it's there for defense.
	*/
}

// This function should be used to register concrete types that will appear in
// interface fields/elements to be encoded/decoded by go-amino.
// Usage:
// `amino.RegisterConcrete(MyStruct1{}, "MyStruct1", nil)`
func (cdc *Codec) RegisterConcrete(o interface{}, name string, copts *ConcreteOptions) {
	cdc.assertNotSealed()

	var pointerPreferred bool

	// Get reflect.Type.
	rt := reflect.TypeOf(o)
	if rt.Kind() == reflect.Interface {
		panic(fmt.Sprintf("expected a non-interface: %v", rt))
	}
	if rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
		if rt.Kind() == reflect.Ptr {
			// We can encode/decode pointer-pointers, but not register them.
			panic(fmt.Sprintf("registering pointer-pointers not yet supported: *%v", rt))
		}
		if rt.Kind() == reflect.Interface {
			// MARKER: No interface-pointers
			panic(fmt.Sprintf("registering interface-pointers not yet supported: *%v", rt))
		}
		pointerPreferred = true
	}

	// Construct ConcreteInfo.
	var info = cdc.newTypeInfoFromRegisteredConcreteType(rt, pointerPreferred, name, copts)

	// Finally, check conflicts and register.
	func() {
		cdc.mtx.Lock()
		defer cdc.mtx.Unlock()

		cdc.addCheckConflictsWithConcreteNolock(info)
		cdc.setTypeInfoNoLock(info)
	}()
}

func (cdc *Codec) Seal() *Codec {
	cdc.mtx.Lock()
	defer cdc.mtx.Unlock()

	cdc.sealed = true
	return cdc
}

// PrintTypes writes all registered types in a markdown-style table.
// The table's header is:
//
// | Type  | Name | Prefix | Notes |
//
// Where Type is the golang type name and Name is the name the type was registered with.
func (cdc Codec) PrintTypes(out io.Writer) error {
	cdc.mtx.RLock()
	defer cdc.mtx.RUnlock()
	// print header
	if _, err := io.WriteString(out, "| Type | Name | Prefix | Length | Notes |\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(out, "| ---- | ---- | ------ | ----- | ------ |\n"); err != nil {
		return err
	}
	// only print concrete types for now (if we want everything, we can iterate over the typeInfos map instead)
	for _, i := range cdc.concreteInfos {
		io.WriteString(out, "| ")
		// TODO(ismail): optionally create a link to code on github:
		if _, err := io.WriteString(out, i.Type.Name()); err != nil {
			return err
		}
		if _, err := io.WriteString(out, " | "); err != nil {
			return err
		}
		if _, err := io.WriteString(out, i.Name); err != nil {
			return err
		}
		if _, err := io.WriteString(out, " | "); err != nil {
			return err
		}
		if _, err := io.WriteString(out, fmt.Sprintf("0x%X", i.Prefix)); err != nil {
			return err
		}
		if _, err := io.WriteString(out, " | "); err != nil {
			return err
		}

		if _, err := io.WriteString(out, getLengthStr(i)); err != nil {
			return err
		}

		if _, err := io.WriteString(out, " | "); err != nil {
			return err
		}
		// empty notes table data by default // TODO(ismail): make this configurable

		io.WriteString(out, " |\n")
	}
	// finish table
	return nil
}

// A heuristic to guess the size of a registered type and return it as a string.
// If the size is not fixed it returns "variable".
func getLengthStr(info *TypeInfo) string {
	switch info.Type.Kind() {
	case reflect.Array,
		reflect.Int8,
		reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128:
		s := info.Type.Size()
		return fmt.Sprintf("0x%X", s)
	default:
		return "variable"
	}
}

//----------------------------------------

func (cdc *Codec) assertNotSealed() {
	cdc.mtx.Lock()
	defer cdc.mtx.Unlock()

	if cdc.sealed {
		panic("codec sealed")
	}
}

func (cdc *Codec) setTypeInfoNoLock(info *TypeInfo) {

	if info.Type.Kind() == reflect.Ptr {
		panic(fmt.Sprintf("unexpected pointer type"))
	}
	if _, ok := cdc.typeInfos[info.Type]; ok {
		//panic(fmt.Sprintf("TypeInfo already exists for %v", info.Type))
		return
	}

	cdc.typeInfos[info.Type] = info
	if info.Type.Kind() == reflect.Interface {
		cdc.interfaceInfos = append(cdc.interfaceInfos, info)
	} else if info.Registered {
		cdc.concreteInfos = append(cdc.concreteInfos, info)
		disfix := info.GetDisfix()
		if existing, ok := cdc.disfixToTypeInfo[disfix]; ok {
			panic(fmt.Sprintf("disfix <%X> already registered for %v", disfix, existing.Type))
		}
		if existing, ok := cdc.nameToTypeInfo[info.Name]; ok {
			panic(fmt.Sprintf("name <%s> already registered for %v", info.Name, existing.Type))
		}
		cdc.disfixToTypeInfo[disfix] = info
		cdc.nameToTypeInfo[info.Name] = info
		//cdc.prefixToTypeInfos[prefix] =
		//	append(cdc.prefixToTypeInfos[prefix], info)
	}
}

func (cdc *Codec) getRegistedTypeInfoWLock(rt reflect.Type) (info *TypeInfo, registed bool) {
	cdc.mtx.Lock() // requires wlock because we might set.
	defer cdc.mtx.Unlock()

	// Dereference pointer type.
	for rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}

	info, ok := cdc.typeInfos[rt]
	if !ok {
		return nil, false
	}
	return info, true
}

func (cdc *Codec) getTypeInfoWlock(rt reflect.Type) (info *TypeInfo, err error) {
	cdc.mtx.Lock() // requires wlock because we might set.
	defer cdc.mtx.Unlock()

	// Dereference pointer type.
	for rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}

	info, ok := cdc.typeInfos[rt]
	if !ok {
		if rt.Kind() == reflect.Interface {
			err = fmt.Errorf("Unregistered interface %v", rt)
			return
		}

		info = cdc.newTypeInfoUnregistered(rt)
		cdc.setTypeInfoNoLock(info)
	}
	return info, nil
}

// iinfo: TypeInfo for the interface for which we must decode a
// concrete type with prefix bytes pb.
func (cdc *Codec) getTypeInfoFromPrefixRlock(iinfo *TypeInfo, pb PrefixBytes) (info *TypeInfo, err error) {
	cdc.mtx.RLock()
	defer cdc.mtx.RUnlock()

	infos, ok := iinfo.Implementers[pb]
	if !ok {
		err = fmt.Errorf("unrecognized prefix bytes %X", pb)
		return
	}
	if len(infos) > 1 {
		err = fmt.Errorf("conflicting concrete types registered for %X: e.g. %v and %v", pb, infos[0].Type, infos[1].Type)
		return
	}
	info = infos[0]
	return
}

func (cdc *Codec) getTypeInfoFromDisfixRlock(df DisfixBytes) (info *TypeInfo, err error) {
	cdc.mtx.RLock()
	defer cdc.mtx.RUnlock()

	info, ok := cdc.disfixToTypeInfo[df]
	if !ok {
		err = fmt.Errorf("unrecognized disambiguation+prefix bytes %X", df)
		return
	}
	return
}

func (cdc *Codec) getTypeInfoFromNameRlock(name string) (info *TypeInfo, err error) {
	cdc.mtx.RLock()
	defer cdc.mtx.RUnlock()

	info, ok := cdc.nameToTypeInfo[name]
	if !ok {
		err = fmt.Errorf("unrecognized concrete type name %s", name)
		return
	}
	return
}

func (cdc *Codec) parseStructInfo(rt reflect.Type) (sinfo StructInfo) {
	if rt.Kind() != reflect.Struct {
		panic("should not happen")
	}

	var infos = make([]FieldInfo, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		var field = rt.Field(i)
		var ftype = field.Type
		var unpackedList = false
		if !isExported(field) {
			continue // field is unexported
		}
		skip, fopts := cdc.parseFieldOptions(field)
		if skip {
			continue // e.g. json:"-"
		}
		if ftype.Kind() == reflect.Array || ftype.Kind() == reflect.Slice {
			if ftype.Elem().Kind() == reflect.Uint8 {
				// These get handled by our optimized methods,
				// encodeReflectBinaryByte[Slice/Array].
				unpackedList = false
			} else {
				etype := ftype.Elem()
				for etype.Kind() == reflect.Ptr {
					etype = etype.Elem()
				}
				typ3 := typeToTyp3(etype, fopts)
				if typ3 == Typ3_ByteLength {
					unpackedList = true
				}
			}
		}
		// NOTE: This is going to change a bit.
		// NOTE: BinFieldNum starts with 1.
		fopts.BinFieldNum = uint32(len(infos) + 1)
		fieldInfo := FieldInfo{
			Name:         field.Name, // Mostly for debugging.
			Index:        i,
			Type:         ftype,
			ZeroValue:    reflect.Zero(ftype),
			UnpackedList: unpackedList,
			FieldOptions: fopts,
		}
		checkUnsafe(fieldInfo)
		infos = append(infos, fieldInfo)
	}
	sinfo = StructInfo{infos}
	return
}

func (cdc *Codec) parseFieldOptions(field reflect.StructField) (skip bool, fopts FieldOptions) {
	binTag := field.Tag.Get("binary")
	aminoTag := field.Tag.Get("amino")
	jsonTag := field.Tag.Get("json")

	// If `json:"-"`, don't encode.
	// NOTE: This skips binary as well.
	if jsonTag == "-" {
		skip = true
		return
	}

	// Get JSON field name.
	jsonTagParts := strings.Split(jsonTag, ",")
	if jsonTagParts[0] == "" {
		fopts.JSONName = field.Name
	} else {
		fopts.JSONName = jsonTagParts[0]
	}

	// Get JSON omitempty.
	if len(jsonTagParts) > 1 {
		if jsonTagParts[1] == "omitempty" {
			fopts.JSONOmitEmpty = true
		}
	}

	// Parse binary tags.
	if binTag == "fixed64" { // TODO: extend
		fopts.BinFixed64 = true
	} else if binTag == "fixed32" {
		fopts.BinFixed32 = true
	}

	// Parse amino tags.
	if aminoTag == "unsafe" {
		fopts.Unsafe = true
	}

	return
}

// Constructs a *TypeInfo automatically, not from registration.
func (cdc *Codec) newTypeInfoUnregistered(rt reflect.Type) *TypeInfo {
	if rt.Kind() == reflect.Ptr {
		panic("unexpected pointer type") // should not happen.
	}
	if rt.Kind() == reflect.Interface {
		panic("unexpected interface type") // should not happen.
	}

	var info = new(TypeInfo)
	info.Type = rt
	info.PtrToType = reflect.PtrTo(rt)
	info.ZeroValue = reflect.Zero(rt)
	info.ZeroProto = reflect.Zero(rt).Interface()
	if rt.Kind() == reflect.Struct {
		info.StructInfo = cdc.parseStructInfo(rt)
	}
	if rm, ok := rt.MethodByName("MarshalAmino"); ok {
		info.ConcreteInfo.IsAminoMarshaler = true
		info.ConcreteInfo.AminoMarshalReprType = marshalAminoReprType(rm)
	}
	if rm, ok := reflect.PtrTo(rt).MethodByName("UnmarshalAmino"); ok {
		info.ConcreteInfo.IsAminoUnmarshaler = true
		info.ConcreteInfo.AminoUnmarshalReprType = unmarshalAminoReprType(rm)
	}
	return info
}

func (cdc *Codec) newTypeInfoFromInterfaceType(rt reflect.Type, iopts *InterfaceOptions) *TypeInfo {
	if rt.Kind() != reflect.Interface {
		panic(fmt.Sprintf("expected interface type, got %v", rt))
	}

	var info = new(TypeInfo)
	info.Type = rt
	info.PtrToType = reflect.PtrTo(rt)
	info.ZeroValue = reflect.Zero(rt)
	info.ZeroProto = reflect.Zero(rt).Interface()
	info.InterfaceInfo.Implementers = make(map[PrefixBytes][]*TypeInfo)
	if iopts != nil {
		info.InterfaceInfo.InterfaceOptions = *iopts
		info.InterfaceInfo.Priority = make([]DisfixBytes, len(iopts.Priority))
		// Construct Priority []DisfixBytes
		for i, name := range iopts.Priority {
			disamb, prefix := nameToDisfix(name)
			disfix := toDisfix(disamb, prefix)
			info.InterfaceInfo.Priority[i] = disfix
		}
	}
	return info
}

func (cdc *Codec) newTypeInfoFromRegisteredConcreteType(rt reflect.Type, pointerPreferred bool, name string, copts *ConcreteOptions) *TypeInfo {
	if rt.Kind() == reflect.Interface ||
		rt.Kind() == reflect.Ptr {
		panic(fmt.Sprintf("expected non-interface non-pointer concrete type, got %v", rt))
	}

	var info = cdc.newTypeInfoUnregistered(rt)
	info.ConcreteInfo.Registered = true
	info.ConcreteInfo.PointerPreferred = pointerPreferred
	info.ConcreteInfo.Name = name
	info.ConcreteInfo.Disamb = nameToDisamb(name)
	info.ConcreteInfo.Prefix = nameToPrefix(name)
	if copts != nil {
		info.ConcreteOptions = *copts
	}
	return info
}

// Find all conflicting prefixes for concrete types
// that "implement" the interface.  "Implement" in quotes because
// we only consider the pointer, for extra safety.
func (cdc *Codec) collectImplementersNolock(info *TypeInfo) {
	for _, cinfo := range cdc.concreteInfos {
		if cinfo.PtrToType.Implements(info.Type) {
			info.Implementers[cinfo.Prefix] = append(
				info.Implementers[cinfo.Prefix], cinfo)
		}
	}
}

// Ensure that prefix-conflicting implementing concrete types
// are all registered in the priority list.
// Returns an error if a disamb conflict is found.
func (cdc *Codec) checkConflictsInPrioNolock(iinfo *TypeInfo) error {

	for PrefixBytes, cinfos := range iinfo.Implementers {
		if len(cinfos) < 2 {
			continue
		}
		if len(cinfos) == 2 && cinfos[0].Type == cinfos[1].Type {
			//the same type register twice
			iinfo.Implementers[PrefixBytes] = []*TypeInfo{cinfos[0]}
			return nil
		}
		for _, cinfo := range cinfos {
			var inPrio = false
			for _, disfix := range iinfo.InterfaceInfo.Priority {
				if cinfo.GetDisfix() == disfix {
					inPrio = true
				}
			}
			if !inPrio {
				return fmt.Errorf("%v conflicts with %v other(s). Add it to the priority list for %v",
					cinfo.Type, len(cinfos), iinfo.Type)
			}
		}
	}
	return nil
}

func (cdc *Codec) addCheckConflictsWithConcreteNolock(cinfo *TypeInfo) {

	// Iterate over registered interfaces that this "implements".
	// "Implement" in quotes because we only consider the pointer, for extra
	// safety.
	for _, iinfo := range cdc.interfaceInfos {
		if !cinfo.PtrToType.Implements(iinfo.Type) {
			continue
		}

		// Add cinfo to iinfo.Implementers.
		var origImpls = iinfo.Implementers[cinfo.Prefix]
		iinfo.Implementers[cinfo.Prefix] = append(origImpls, cinfo)

		// Finally, check that all conflicts are in `.Priority`.
		// NOTE: This could be optimized, but it's non-trivial.
		err := cdc.checkConflictsInPrioNolock(iinfo)
		if err != nil {
			// Return to previous state.
			iinfo.Implementers[cinfo.Prefix] = origImpls
			panic(err)
		}
	}
}

func (cdc *Codec) MarshalJSON(o interface{}) ([]byte, error) {
	rv := reflect.ValueOf(o)
	if rv.Kind() == reflect.Invalid {
		return []byte("null"), nil
	}
	rt := rv.Type()
	w := new(bytes.Buffer)
	info, err := cdc.getTypeInfoWlock(rt)
	if err != nil {
		return nil, err
	}

	// Write the disfix wrapper if it is a registered concrete type.
	if info.Registered {
		// Part 1:
		err = writeStr(w, _fmt(`{"type":"%s","value":`, info.Name))
		if err != nil {
			return nil, err
		}
	}

	// Write the rest from rv.
	if err := cdc.encodeReflectJSON(w, info, rv, FieldOptions{}); err != nil {
		return nil, err
	}

	// disfix wrapper continued...
	if info.Registered {
		// Part 2:
		err = writeStr(w, `}`)
		if err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (cdc *Codec) UnmarshalJSON(bz []byte, ptr interface{}) error {
	if len(bz) == 0 {
		return errors.New("UnmarshalJSON cannot decode empty bytes")
	}

	rv := reflect.ValueOf(ptr)
	if rv.Kind() != reflect.Ptr {
		return errors.New("UnmarshalJSON expects a pointer")
	}
	rv = rv.Elem()
	rt := rv.Type()
	info, err := cdc.getTypeInfoWlock(rt)
	if err != nil {
		return err
	}
	// If registered concrete, consume and verify type wrapper.
	if info.Registered {
		// Consume type wrapper info.
		name, bz_, err := decodeInterfaceJSON(bz)
		if err != nil {
			return err
		}
		// Check name against info.
		if name != info.Name {
			return fmt.Errorf("UnmarshalJSON wants to decode a %v but found a %v", info.Name, name)
		}
		bz = bz_
	}
	return cdc.decodeReflectJSON(bz, info, rv, FieldOptions{})
}

// MarshalJSONIndent calls json.Indent on the output of cdc.MarshalJSON
// using the given prefix and indent string.
func (cdc *Codec) MarshalJSONIndent(o interface{}, prefix, indent string) ([]byte, error) {
	bz, err := cdc.MarshalJSON(o)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = json.Indent(&out, bz, prefix, indent)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

//----------------------------------------
// .String()

func (ti TypeInfo) String() string {
	buf := new(bytes.Buffer)
	buf.Write([]byte("TypeInfo{"))
	buf.Write([]byte(fmt.Sprintf("Type:%v,", ti.Type)))
	if ti.Type.Kind() == reflect.Interface {
		buf.Write([]byte(fmt.Sprintf("Priority:%v,", ti.Priority)))
		buf.Write([]byte("Implementers:{"))
		for pb, cinfos := range ti.Implementers {
			buf.Write([]byte(fmt.Sprintf("\"%X\":", pb)))
			buf.Write([]byte(fmt.Sprintf("%v,", cinfos)))
		}
		buf.Write([]byte("}"))
		buf.Write([]byte(fmt.Sprintf("Priority:%v,", ti.InterfaceOptions.Priority)))
		buf.Write([]byte(fmt.Sprintf("AlwaysDisambiguate:%v,", ti.InterfaceOptions.AlwaysDisambiguate)))
	}
	if ti.Type.Kind() != reflect.Interface {
		if ti.ConcreteInfo.Registered {
			buf.Write([]byte("Registered:true,"))
			buf.Write([]byte(fmt.Sprintf("PointerPreferred:%v,", ti.PointerPreferred)))
			buf.Write([]byte(fmt.Sprintf("Name:\"%v\",", ti.Name)))
			buf.Write([]byte(fmt.Sprintf("Disamb:\"%X\",", ti.Disamb)))
			buf.Write([]byte(fmt.Sprintf("Prefix:\"%X\",", ti.Prefix)))
		} else {
			buf.Write([]byte("Registered:false,"))
		}
		buf.Write([]byte(fmt.Sprintf("AminoMarshalReprType:\"%v\",", ti.AminoMarshalReprType)))
		buf.Write([]byte(fmt.Sprintf("AminoUnmarshalReprType:\"%v\",", ti.AminoUnmarshalReprType)))
		if ti.Type.Kind() == reflect.Struct {
			buf.Write([]byte(fmt.Sprintf("Fields:%v,", ti.Fields)))
		}
	}
	buf.Write([]byte("}"))
	return buf.String()
}

//----------------------------------------
// Misc.

func isExported(field reflect.StructField) bool {
	// Test 1:
	if field.PkgPath != "" {
		return false
	}
	// Test 2:
	var first rune
	for _, c := range field.Name {
		first = c
		break
	}
	// TODO: JAE: I'm not sure that the unicode spec
	// is the correct spec to use, so this might be wrong.
	if !unicode.IsUpper(first) {
		return false
	}
	// Ok, it's exported.
	return true
}

func nameToDisamb(name string) (db DisambBytes) {
	db, _ = nameToDisfix(name)
	return
}

func nameToPrefix(name string) (pb PrefixBytes) {
	_, pb = nameToDisfix(name)
	return
}

func nameToDisfix(name string) (db DisambBytes, pb PrefixBytes) {
	hasher := sha256.New()
	hasher.Write([]byte(name))
	bz := hasher.Sum(nil)
	for bz[0] == 0x00 {
		bz = bz[1:]
	}
	copy(db[:], bz[0:3])
	bz = bz[3:]
	for bz[0] == 0x00 {
		bz = bz[1:]
	}
	copy(pb[:], bz[0:4])
	return
}

func toDisfix(db DisambBytes, pb PrefixBytes) (df DisfixBytes) {
	copy(df[0:3], db[0:3])
	copy(df[3:7], pb[0:4])
	return
}

// Dereference pointer recursively.
// drv: the final non-pointer value (which may be invalid).
// isPtr: whether rv.Kind() == reflect.Ptr.
// isNilPtr: whether a nil pointer at any level.
func derefPointers(rv reflect.Value) (drv reflect.Value, isPtr bool, isNilPtr bool) {
	for rv.Kind() == reflect.Ptr {
		isPtr = true
		if rv.IsNil() {
			isNilPtr = true
			return
		}
		rv = rv.Elem()
	}
	drv = rv
	return
}

func derefPointersType(rt reflect.Type) reflect.Type {
	for rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}
	return rt
}

// constructConcreteType creates the concrete value as
// well as the corresponding settable value for it.
// Return irvSet which should be set on caller's interface rv.
func constructConcreteType(cinfo *TypeInfo) (crv, irvSet reflect.Value) {
	// Construct new concrete type.
	if cinfo.PointerPreferred {
		cPtrRv := reflect.New(cinfo.Type)
		crv = cPtrRv.Elem()
		irvSet = cPtrRv
	} else {
		crv = reflect.New(cinfo.Type).Elem()
		irvSet = crv
	}
	return
}

//----------------------------------------
// Typ3

type Typ3 uint8

const (
	// Typ3 types
	Typ3_Varint     = Typ3(0)
	Typ3_8Byte      = Typ3(1)
	Typ3_ByteLength = Typ3(2)
	//Typ3_Struct     = Typ3(3)
	//Typ3_StructTerm = Typ3(4)
	Typ3_4Byte = Typ3(5)
	//Typ3_List       = Typ3(6)
	//Typ3_Interface  = Typ3(7)
)

func (typ Typ3) String() string {
	switch typ {
	case Typ3_Varint:
		return "(U)Varint"
	case Typ3_8Byte:
		return "8Byte"
	case Typ3_ByteLength:
		return "ByteLength"
	//case Typ3_Struct:
	//	return "Struct"
	//case Typ3_StructTerm:
	//	return "StructTerm"
	case Typ3_4Byte:
		return "4Byte"
	//case Typ3_List:
	//	return "List"
	//case Typ3_Interface:
	//	return "Interface"
	default:
		return fmt.Sprintf("<Invalid Typ3 %X>", byte(typ))
	}
}

// CONTRACT: rt.Kind() != reflect.Ptr
func typeToTyp3(rt reflect.Type, opts FieldOptions) Typ3 {
	switch rt.Kind() {
	case reflect.Interface:
		return Typ3_ByteLength
	case reflect.Array, reflect.Slice:
		return Typ3_ByteLength
	case reflect.String:
		return Typ3_ByteLength
	case reflect.Struct, reflect.Map:
		return Typ3_ByteLength
	case reflect.Int64, reflect.Uint64:
		if opts.BinFixed64 {
			return Typ3_8Byte
		} else {
			return Typ3_Varint
		}
	case reflect.Int32, reflect.Uint32:
		if opts.BinFixed32 {
			return Typ3_4Byte
		} else {
			return Typ3_Varint
		}
	case reflect.Int16, reflect.Int8, reflect.Int,
		reflect.Uint16, reflect.Uint8, reflect.Uint, reflect.Bool:
		return Typ3_Varint
	case reflect.Float64:
		return Typ3_8Byte
	case reflect.Float32:
		return Typ3_4Byte
	default:
		panic(fmt.Sprintf("unsupported field type %v", rt))
	}
}

func checkUnsafe(field FieldInfo) {
	if field.Unsafe {
		return
	}
	switch field.Type.Kind() {
	case reflect.Float32, reflect.Float64:
		panic("floating point types are unsafe for go-amino")
	}
}

func toReprObject(rv reflect.Value) (rrv reflect.Value, err error) {
	var mwrm reflect.Value
	if rv.CanAddr() {
		mwrm = rv.Addr().MethodByName("MarshalAmino")
	} else {
		mwrm = rv.MethodByName("MarshalAmino")
	}
	mwouts := mwrm.Call(nil)
	if !mwouts[1].IsNil() {
		err = mwouts[1].Interface().(error)
		if err != nil {
			return
		}
	}
	rrv = mwouts[0]
	return
}

func marshalAminoReprType(rm reflect.Method) (rrt reflect.Type) {
	// Verify form of this method.
	if rm.Type.NumIn() != 1 {
		panic(fmt.Sprintf("MarshalAmino should have 1 input parameters (including receiver); got %v", rm.Type))
	}
	if rm.Type.NumOut() != 2 {
		panic(fmt.Sprintf("MarshalAmino should have 2 output parameters; got %v", rm.Type))
	}
	if out := rm.Type.Out(1); out != errorType {
		panic(fmt.Sprintf("MarshalAmino should have second output parameter of error type, got %v", out))
	}
	rrt = rm.Type.Out(0)
	if rrt.Kind() == reflect.Ptr {
		panic(fmt.Sprintf("Representative objects cannot be pointers; got %v", rrt))
	}
	return
}

func unmarshalAminoReprType(rm reflect.Method) (rrt reflect.Type) {
	// Verify form of this method.
	if rm.Type.NumIn() != 2 {
		panic(fmt.Sprintf("UnmarshalAmino should have 2 input parameters (including receiver); got %v", rm.Type))
	}
	if in1 := rm.Type.In(0); in1.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("UnmarshalAmino first input parameter should be pointer type but got %v", in1))
	}
	if rm.Type.NumOut() != 1 {
		panic(fmt.Sprintf("UnmarshalAmino should have 1 output parameters; got %v", rm.Type))
	}
	if out := rm.Type.Out(0); out != errorType {
		panic(fmt.Sprintf("UnmarshalAmino should have first output parameter of error type, got %v", out))
	}
	rrt = rm.Type.In(1)
	if rrt.Kind() == reflect.Ptr {
		panic(fmt.Sprintf("Representative objects cannot be pointers; got %v", rrt))
	}
	return
}

func isNil(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Interface, reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func addDisfix(val reflect.Value, w *encbuf) (err error) {
	var rt = val.Type()
	var cinfo *TypeInfo
	cinfo, registed := cdc.getRegistedTypeInfoWLock(rt)
	if registed && cinfo.Registered {
		// Write disambiguation bytes.
		w.str = append(w.str, cinfo.Disamb[:]...)
		// Write prefix+typ3 bytes.
		w.str = append(w.str, cinfo.Prefix[:]...)
	}
	return
}

func consumeDisfix(s *Stream, rv reflect.Value) error {
	var rt = rv.Type()
	var cinfo *TypeInfo
	var err error
	cinfo, registed := cdc.getRegistedTypeInfoWLock(rt)
	if registed && cinfo.Registered {
		var bz [7]byte
		for i := 0; i < 7; i++ {
			bz[i], err = s.readByte()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func writeCDCInterface(rv reflect.Value, w *encbuf) (err error) {

	drt := derefPointersType(rv.Type())
	// Get *TypeInfo for interface type.
	_, isRegisted := cdc.getRegistedTypeInfoWLock(drt)
	if !isRegisted {
		//if interface not regist, go origin logic
		return writeInterface(rv, w)
	}

	// Special case when rv is nil, write 0x00.
	if rv.IsNil() {
		w.str = append(w.str, []byte{0x00}...)
		return
	}

	// Get concrete non-pointer reflect value & type.
	crv, _, isNilPtr := derefPointers(rv.Elem())
	if isNilPtr || crv.Kind() == reflect.Interface {
		// See "MARKER: No interface-pointers" in codec.go
		panic("should not happen")
	}

	var crt = crv.Type()

	// Get *TypeInfo for concrete type.
	var cinfo *TypeInfo
	cinfo, isRegisted = cdc.getRegistedTypeInfoWLock(crt)
	if !isRegisted || !cinfo.Registered {
		err = fmt.Errorf("Cannot encode unregistered concrete type %v", crt)
		return
	}

	// Write disambiguation bytes.
	w.str = append(w.str, cinfo.Disamb[:]...)

	// Write prefix+typ3 bytes.
	w.str = append(w.str, cinfo.Prefix[:]...)

	// Write actual concrete value.
	typeCacheMutex.Lock()
	info, err := cachedTypeInfo1(crt, tags{})
	typeCacheMutex.Unlock()
	return info.writer(crv, w)
}

func decodeCDCInterface(s *Stream, rv reflect.Value) (err error) {

	drt := derefPointersType(rv.Type())
	// Get *TypeInfo for interface type.
	_, isRegisted := cdc.getRegistedTypeInfoWLock(drt)
	if !isRegisted {
		//if interface not regist, go origin logic
		return decodeInterface(s, rv)
	}

	//for case []interface{}
	var tos *listpos
	if len(s.stack) > 0 {
		tos = &s.stack[len(s.stack)-1]
	}
	if tos != nil && tos.pos == tos.size {
		return EOL
	}
	// Consume disambiguation / prefix+typ3 bytes.
	var bz [7]byte
	bz[0], err = s.readByte()
	if err != nil {
		return err
	}
	if bz[0] == 0x00 {
		rv.Set(reflect.Zero(rv.Type()))
		return err
	}
	for i := 1; i < 7; i++ {
		bz[i], err = s.readByte()
		if err != nil {
			return err
		}
	}

	// Get concrete type info from disfix/prefix.
	var cinfo *TypeInfo
	var disfixbyte DisfixBytes
	copy(disfixbyte[:], bz[:])
	cinfo, err = cdc.getTypeInfoFromDisfixRlock(disfixbyte)
	if err != nil {
		return
	}

	// Construct the concrete type.
	var crv, irvSet = constructConcreteType(cinfo)

	// Decode into the concrete type.
	typeCacheMutex.Lock()
	info, err := cachedTypeInfo1(crv.Type(), tags{})
	typeCacheMutex.Unlock()
	info.decoder(s, crv)

	// We need to set here, for when !PointerPreferred and the type
	// is say, an array of bytes (e.g. [32]byte), then we must call
	// rv.Set() *after* the value was acquired.
	// NOTE: rv.Set() should succeed because it was validated
	// already during Register[Interface/Concrete].
	rv.Set(irvSet)
	return
}

//RegisterInterface wrapper for cdc.RegisterInterface
func RegisterInterface(ptr interface{}, opts *InterfaceOptions) {
	cdc.RegisterInterface(ptr, opts)
}

//RegisterConcrete wrapper for cdc.RegisterConcrete
func RegisterConcrete(o interface{}, name string, opts *ConcreteOptions) {
	cdc.RegisterConcrete(o, name, opts)
}

//MarshalJSON wrapper for cdc.MarshalJSON
func MarshalJSON(o interface{}) ([]byte, error) {
	return cdc.MarshalJSON(o)
}

//UnmarshalJSON wrapper for cdc.UnmarshalJSON
func UnmarshalJSON(bz []byte, ptr interface{}) error {
	return cdc.UnmarshalJSON(bz, ptr)
}

//MarshalJSONIndent wrapper for cdc.MarshalJSONIndent
func MarshalJSONIndent(o interface{}, prefix, indent string) ([]byte, error) {
	return cdc.MarshalJSONIndent(o, prefix, indent)
}

//PrintTypes wrapper for cdc.PrintTypes
func PrintTypes(out io.Writer) error {
	return cdc.PrintTypes(out)
}

//EncodeByteSlice wrapper for cdc.EncodeByteSlice, but use bal encode
func EncodeByteSlice(w io.Writer, bz []byte) (err error) {
	_, err = EncodeWriter(w, bz)
	return err
}

//EncodeUvarint wrapper for cdc.EncodeUvarint, but use bal encode
func EncodeUvarint(w io.Writer, u uint64) (err error) {
	_, err = EncodeWriter(w, u)
	return err
}