package enclave

// #cgo LDFLAGS: -framework CoreFoundation
// #cgo LDFLAGS: -framework Security
// #include <CoreFoundation/CoreFoundation.h>
// #include <Security/Security.h>
import "C"
import "unsafe"

type autorelease []C.CFTypeRef

func (ar *autorelease) Close() error {
	for _, ptr := range *ar {
		if (unsafe.Pointer)(ptr) != nil {
			C.CFRelease(ptr)
		}
	}
	return nil
}

func (ar *autorelease) Add(ptr C.CFTypeRef) C.CFTypeRef {
	*ar = append(*ar, ptr)
	return ptr
}

func (ar *autorelease) AddDict(m map[C.CFStringRef]C.CFTypeRef) C.CFMutableDictionaryRef {
	ret := C.CFDictionaryCreateMutable(
		C.kCFAllocatorDefault,
		0,
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks,
	)

	for k, v := range m {
		C.CFDictionaryAddValue(ret, unsafe.Pointer(k), unsafe.Pointer(v))
	}

	ar.Add(C.CFTypeRef(unsafe.Pointer(ret)))
	return ret
}

func (ar *autorelease) AddString(s string) C.CFStringRef {
	ret := C.CFStringCreateWithCString(
		C.kCFAllocatorDefault,
		(*C.char)(unsafe.Pointer(&[]byte(s)[0])),
		C.kCFStringEncodingUTF8,
	)

	ar.Add(C.CFTypeRef(unsafe.Pointer(ret)))
	return ret
}

func (ar *autorelease) AddNumber(i int) C.CFNumberRef {
	ret := C.CFNumberCreate(
		C.kCFAllocatorDefault,
		C.kCFNumberIntType,
		unsafe.Pointer(&i),
	)

	ar.Add(C.CFTypeRef(unsafe.Pointer(ret)))
	return ret
}

func (ar *autorelease) AddStringData(s string) C.CFDataRef {
	ret := C.CFDataCreate(
		C.kCFAllocatorDefault,
		(*C.uint8_t)(unsafe.Pointer(&[]byte(s)[0])),
		C.CFIndex(len(s)),
	)

	ar.Add(C.CFTypeRef(unsafe.Pointer(ret)))
	return ret
}

func (ar *autorelease) AddBytes(bytes []byte) C.CFDataRef {
	ret := C.CFDataCreate(
		C.kCFAllocatorDefault,
		(*C.uint8_t)(unsafe.Pointer(&bytes[0])),
		C.CFIndex(len(bytes)),
	)
	ar.Add(C.CFTypeRef(unsafe.Pointer(ret)))
	return ret
}
