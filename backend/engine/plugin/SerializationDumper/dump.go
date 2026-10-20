package SerializationDumper

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Java 对象序列化流（java.io.ObjectOutputStream）的纯 Go 解析，输出格式对齐 NickstaDB/SerializationDumper。
// 无需 java 运行环境。

const (
	tcNull           = 0x70
	tcReference      = 0x71
	tcClassDesc      = 0x72
	tcObject         = 0x73
	tcString         = 0x74
	tcArray          = 0x75
	tcClass          = 0x76
	tcBlockData      = 0x77
	tcEndBlockData   = 0x78
	tcReset          = 0x79
	tcBlockDataLong  = 0x7a
	tcException      = 0x7b
	tcLongString     = 0x7c
	tcProxyClassDesc = 0x7d
	tcEnum           = 0x7e
	baseHandle       = 0x7e0000

	scWriteMethod  = 0x01
	scSerializable = 0x02
	scExternalize  = 0x04
	scBlockData    = 0x08
	scEnum         = 0x10
)

var tcNames = map[byte]string{
	tcNull: "TC_NULL", tcReference: "TC_REFERENCE", tcClassDesc: "TC_CLASSDESC", tcObject: "TC_OBJECT",
	tcString: "TC_STRING", tcArray: "TC_ARRAY", tcClass: "TC_CLASS", tcBlockData: "TC_BLOCKDATA",
	tcEndBlockData: "TC_ENDBLOCKDATA", tcReset: "TC_RESET", tcBlockDataLong: "TC_BLOCKDATALONG",
	tcException: "TC_EXCEPTION", tcLongString: "TC_LONGSTRING", tcProxyClassDesc: "TC_PROXYCLASSDESC", tcEnum: "TC_ENUM",
}

var fieldTypeNames = map[byte]string{
	'B': "Byte", 'C': "Char", 'D': "Double", 'F': "Float", 'I': "Int", 'J': "Long", 'S': "Short", 'Z': "Boolean",
	'[': "Array", 'L': "Object",
}

type field struct {
	typ  byte
	name string
}

type classDesc struct {
	name   string
	flags  byte
	fields []field
	super  *classDesc
}

type dumper struct {
	b       []byte
	pos     int
	sb      strings.Builder
	handle  int
	handles map[int]*classDesc
}

type dumpError struct{ msg string }

func (d *dumper) fail(format string, a ...interface{}) {
	panic(dumpError{fmt.Sprintf(format, a...)})
}

func (d *dumper) read(n int) []byte {
	if n < 0 || d.pos+n > len(d.b) {
		d.fail("数据不足: 需要 %d 字节, 偏移 %d, 总长 %d", n, d.pos, len(d.b))
	}
	r := d.b[d.pos : d.pos+n]
	d.pos += n
	return r
}

func (d *dumper) peek() byte {
	if d.pos >= len(d.b) {
		d.fail("数据不足: 偏移 %d", d.pos)
	}
	return d.b[d.pos]
}

func (d *dumper) out(indent int, format string, a ...interface{}) {
	d.sb.WriteString(strings.Repeat("  ", indent))
	fmt.Fprintf(&d.sb, format, a...)
	d.sb.WriteByte('\n')
}

func spaced(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return "0x" + strings.Join(parts, " ")
}

func (d *dumper) newHandle(indent int, cd *classDesc) int {
	h := baseHandle + d.handle
	d.handle++
	d.handles[h] = cd
	d.out(indent, "newHandle %s", spaced([]byte{byte(h >> 24), byte(h >> 16), byte(h >> 8), byte(h)}))
	return h
}

// utf 读取 2 字节长度的 UTF 字符串
func (d *dumper) utf(indent int) string {
	lb := d.read(2)
	n := int(binary.BigEndian.Uint16(lb))
	d.out(indent, "Length - %d - %s", n, spaced(lb))
	s := d.read(n)
	d.out(indent, "Value - %s - 0x%s", string(s), hex.EncodeToString(s))
	return string(s)
}

func (d *dumper) longUTF(indent int) string {
	lb := d.read(8)
	n := binary.BigEndian.Uint64(lb)
	d.out(indent, "Length - %d - %s", n, spaced(lb))
	if n > uint64(len(d.b)) {
		d.fail("字符串长度非法: %d", n)
	}
	s := d.read(int(n))
	d.out(indent, "Value - %s - 0x%s", string(s), hex.EncodeToString(s))
	return string(s)
}

func tcLabel(tc byte) string {
	if n, ok := tcNames[tc]; ok {
		return fmt.Sprintf("%s - 0x%02x", n, tc)
	}
	return fmt.Sprintf("UNKNOWN - 0x%02x", tc)
}

// content 解析一个 content 元素；返回其 classDesc（仅当元素是 classDesc / 引用 classDesc 时）
func (d *dumper) content(indent int) *classDesc {
	tc := d.read(1)[0]
	switch tc {
	case tcNull:
		d.out(indent, "%s", tcLabel(tc))
	case tcReference:
		return d.reference(indent)
	case tcString:
		d.out(indent, "%s", tcLabel(tc))
		d.newHandle(indent+1, nil)
		d.utf(indent + 1)
	case tcLongString:
		d.out(indent, "%s", tcLabel(tc))
		d.newHandle(indent+1, nil)
		d.longUTF(indent + 1)
	case tcObject:
		d.out(indent, "%s", tcLabel(tc))
		d.object(indent + 1)
	case tcArray:
		d.out(indent, "%s", tcLabel(tc))
		d.array(indent + 1)
	case tcEnum:
		d.out(indent, "%s", tcLabel(tc))
		d.classDescElem(indent + 1)
		d.newHandle(indent+1, nil)
		d.content(indent + 1)
	case tcClass:
		d.out(indent, "%s", tcLabel(tc))
		d.classDescElem(indent + 1)
		d.newHandle(indent+1, nil)
	case tcClassDesc, tcProxyClassDesc:
		d.pos--
		return d.classDescElem(indent)
	case tcBlockData:
		d.out(indent, "%s", tcLabel(tc))
		lb := d.read(1)
		d.out(indent+1, "Length - %d - %s", lb[0], spaced(lb))
		d.out(indent+1, "Contents - 0x%s", hex.EncodeToString(d.read(int(lb[0]))))
	case tcBlockDataLong:
		d.out(indent, "%s", tcLabel(tc))
		lb := d.read(4)
		n := binary.BigEndian.Uint32(lb)
		d.out(indent+1, "Length - %d - %s", n, spaced(lb))
		d.out(indent+1, "Contents - 0x%s", hex.EncodeToString(d.read(int(n))))
	case tcReset:
		d.out(indent, "%s", tcLabel(tc))
		d.handle = 0
		d.handles = map[int]*classDesc{}
	case tcException:
		d.out(indent, "%s", tcLabel(tc))
		d.handle = 0
		d.handles = map[int]*classDesc{}
		d.content(indent + 1)
	default:
		d.fail("未知的 content 类型 0x%02x (偏移 %d)", tc, d.pos-1)
	}
	return nil
}

func (d *dumper) reference(indent int) *classDesc {
	d.out(indent, "%s", tcLabel(tcReference))
	hb := d.read(4)
	h := int(binary.BigEndian.Uint32(hb))
	d.out(indent+1, "Handle - %d - %s", h, spaced(hb))
	return d.handles[h]
}

// classDescElem 解析 classDesc 元素（TC_CLASSDESC / TC_PROXYCLASSDESC / TC_NULL / TC_REFERENCE）
func (d *dumper) classDescElem(indent int) *classDesc {
	tc := d.read(1)[0]
	switch tc {
	case tcNull:
		d.out(indent, "%s", tcLabel(tc))
		return nil
	case tcReference:
		return d.reference(indent)
	case tcClassDesc:
		d.out(indent, "%s", tcLabel(tc))
		cd := &classDesc{}
		d.out(indent+1, "className")
		cd.name = d.utf(indent + 2)
		sid := d.read(8)
		d.out(indent+1, "serialVersionUID - %s", spaced(sid))
		d.newHandle(indent+1, cd)
		cd.flags = d.read(1)[0]
		d.out(indent+1, "classDescFlags - 0x%02x - %s", cd.flags, flagNames(cd.flags))
		fc := d.read(2)
		n := int(binary.BigEndian.Uint16(fc))
		d.out(indent+1, "fieldCount - %d - %s", n, spaced(fc))
		if n > 0 {
			d.out(indent+1, "Fields")
		}
		for i := 0; i < n; i++ {
			d.out(indent+2, "%d:", i)
			t := d.read(1)[0]
			tn, ok := fieldTypeNames[t]
			if !ok {
				d.fail("未知的字段类型 0x%02x", t)
			}
			d.out(indent+3, "%s - %c - 0x%02x", tn, t, t)
			d.out(indent+3, "fieldName")
			f := field{typ: t, name: d.utf(indent + 4)}
			if t == 'L' || t == '[' {
				d.out(indent+3, "className1")
				d.content(indent + 4)
			}
			cd.fields = append(cd.fields, f)
		}
		d.out(indent+1, "classAnnotations")
		d.annotations(indent + 2)
		d.out(indent+1, "superClassDesc")
		cd.super = d.classDescElem(indent + 2)
		return cd
	case tcProxyClassDesc:
		d.out(indent, "%s", tcLabel(tc))
		cd := &classDesc{name: "<proxy>", flags: scSerializable}
		d.newHandle(indent+1, cd)
		cb := d.read(4)
		n := int(binary.BigEndian.Uint32(cb))
		d.out(indent+1, "Interface count - %d - %s", n, spaced(cb))
		d.out(indent+1, "proxyInterfaceNames")
		for i := 0; i < n; i++ {
			d.out(indent+2, "%d:", i)
			d.utf(indent + 3)
		}
		d.out(indent+1, "classAnnotations")
		d.annotations(indent + 2)
		d.out(indent+1, "superClassDesc")
		cd.super = d.classDescElem(indent + 2)
		return cd
	}
	d.fail("期望 classDesc, 实际 0x%02x (偏移 %d)", tc, d.pos-1)
	return nil
}

func flagNames(f byte) string {
	var p []string
	for _, e := range []struct {
		bit  byte
		name string
	}{{scWriteMethod, "SC_WRITE_METHOD"}, {scSerializable, "SC_SERIALIZABLE"}, {scExternalize, "SC_EXTERNALIZABLE"}, {scBlockData, "SC_BLOCK_DATA"}, {scEnum, "SC_ENUM"}} {
		if f&e.bit != 0 {
			p = append(p, e.name)
		}
	}
	return strings.Join(p, " | ")
}

// annotations 解析 content* TC_ENDBLOCKDATA
func (d *dumper) annotations(indent int) {
	for {
		if d.peek() == tcEndBlockData {
			d.out(indent, "%s", tcLabel(d.read(1)[0]))
			return
		}
		d.content(indent)
	}
}

func (d *dumper) object(indent int) {
	cd := d.classDescElem(indent)
	if cd == nil {
		d.fail("对象的 classDesc 为空或引用无效")
	}
	d.newHandle(indent, nil)
	d.out(indent, "classdata")
	// 从最顶层父类到子类
	var chain []*classDesc
	for c := cd; c != nil; c = c.super {
		chain = append(chain, c)
		if len(chain) > 256 {
			d.fail("类继承层级过深")
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		c := chain[i]
		d.out(indent+1, "%s", c.name)
		switch {
		case c.flags&scSerializable != 0:
			d.out(indent+2, "values")
			for _, f := range c.fields {
				d.out(indent+3, "%s", f.name)
				d.fieldValue(indent+4, f.typ)
			}
			if c.flags&scWriteMethod != 0 {
				d.out(indent+2, "objectAnnotation")
				d.annotations(indent + 3)
			}
		case c.flags&scExternalize != 0:
			if c.flags&scBlockData == 0 {
				d.fail("类 %s 为 Externalizable 且未使用 block data 协议，无法解析", c.name)
			}
			d.out(indent+2, "externalContents")
			d.annotations(indent + 3)
		default:
			d.fail("类 %s 的标志位 0x%02x 无法识别", c.name, c.flags)
		}
	}
}

func (d *dumper) array(indent int) {
	cd := d.classDescElem(indent)
	if cd == nil || len(cd.name) < 2 || cd.name[0] != '[' {
		d.fail("数组的 classDesc 无效")
	}
	d.newHandle(indent, nil)
	sb := d.read(4)
	n := int(binary.BigEndian.Uint32(sb))
	d.out(indent, "Array size - %d - %s", n, spaced(sb))
	if n < 0 || n > len(d.b) {
		d.fail("数组长度非法: %d", n)
	}
	d.out(indent, "Values")
	t := cd.name[1]
	for i := 0; i < n; i++ {
		d.out(indent+1, "Index %d:", i)
		d.fieldValue(indent+2, t)
	}
}

func (d *dumper) fieldValue(indent int, t byte) {
	switch t {
	case 'B':
		b := d.read(1)
		d.out(indent, "(byte)%d - %s", int8(b[0]), spaced(b))
	case 'C':
		b := d.read(2)
		d.out(indent, "(char)%c - %s", rune(binary.BigEndian.Uint16(b)), spaced(b))
	case 'D':
		b := d.read(8)
		d.out(indent, "(double)%v - %s", math.Float64frombits(binary.BigEndian.Uint64(b)), spaced(b))
	case 'F':
		b := d.read(4)
		d.out(indent, "(float)%v - %s", math.Float32frombits(binary.BigEndian.Uint32(b)), spaced(b))
	case 'I':
		b := d.read(4)
		d.out(indent, "(int)%d - %s", int32(binary.BigEndian.Uint32(b)), spaced(b))
	case 'J':
		b := d.read(8)
		d.out(indent, "(long)%d - %s", int64(binary.BigEndian.Uint64(b)), spaced(b))
	case 'S':
		b := d.read(2)
		d.out(indent, "(short)%d - %s", int16(binary.BigEndian.Uint16(b)), spaced(b))
	case 'Z':
		b := d.read(1)
		d.out(indent, "(boolean)%t - %s", b[0] != 0, spaced(b))
	case 'L', '[':
		d.out(indent, "(%s)", map[byte]string{'L': "object", '[': "array"}[t])
		d.content(indent + 1)
	default:
		d.fail("未知的字段类型 0x%02x", t)
	}
}

var nonHex = regexp.MustCompile(`[\s:]`)

// decodeInput 支持十六进制（可带空格、冒号、0x 前缀）与 base64（rO0AB 开头）
func decodeInput(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("内容为空")
	}
	h := strings.ReplaceAll(nonHex.ReplaceAllString(s, ""), "0x", "")
	if b, err := hex.DecodeString(h); err == nil {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(strings.TrimSpace(s)); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("内容不是合法的十六进制或 base64")
}

// Dump 解析 Java 序列化数据并输出结构；解析中途出错时仍返回已解析的部分，并带 error
func Dump(data []byte) (result string, err error) {
	d := &dumper{b: data, handles: map[int]*classDesc{}}
	defer func() {
		if r := recover(); r != nil {
			de, ok := r.(dumpError)
			if !ok {
				panic(r)
			}
			err = errors.New(de.msg)
			result = d.sb.String()
		}
	}()
	magic := d.read(2)
	if magic[0] != 0xac || magic[1] != 0xed {
		d.fail("不是 Java 序列化数据: 魔数应为 ac ed, 实际 %s", spaced(magic))
	}
	d.out(0, "STREAM_MAGIC - %s", spaced(magic))
	d.out(0, "STREAM_VERSION - %s", spaced(d.read(2)))
	d.out(0, "Contents")
	for d.pos < len(d.b) {
		d.content(1)
	}
	return d.sb.String(), nil
}
