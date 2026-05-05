//go:build darwin

package touchid

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework LocalAuthentication

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>

// rampart_la_can_evaluate returns 1 iff biometrics are reachable and the
// user is enrolled. Sets *errCode to the LAError code when 0 is returned.
static int rampart_la_can_evaluate(int *errCode) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        NSError *err = nil;
        BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                   error:&err];
        *errCode = err ? (int)err.code : 0;
        return ok ? 1 : 0;
    }
}

// rampart_la_evaluate triggers the biometric prompt synchronously by waiting
// on a dispatch_semaphore. Returns 1 on user success, 0 on cancel/failure.
// Sets *errCode to the LAError code (0 on success).
static int rampart_la_evaluate(const char *reason, int *errCode) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        NSString *r = [NSString stringWithUTF8String:reason];
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block BOOL approved = NO;
        __block int code = 0;
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:r
                      reply:^(BOOL success, NSError *err) {
            approved = success;
            if (err) code = (int)err.code;
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        *errCode = code;
        return approved ? 1 : 0;
    }
}
*/
import "C"
import "unsafe"

// laCGoEvaluator is the production Evaluator backed by LAContext.
type laCGoEvaluator struct{}

// CanEvaluate calls -[LAContext canEvaluatePolicy:error:].
func (laCGoEvaluator) CanEvaluate() (bool, int) {
	var code C.int
	ok := C.rampart_la_can_evaluate(&code)
	return ok != 0, int(code)
}

// Evaluate calls -[LAContext evaluatePolicy:localizedReason:reply:] and blocks
// until the reply arrives.
func (laCGoEvaluator) Evaluate(reason string) (bool, int) {
	cs := C.CString(reason)
	defer C.free(unsafe.Pointer(cs))
	var code C.int
	ok := C.rampart_la_evaluate(cs, &code)
	return ok != 0, int(code)
}

// NewChannel returns a Touch ID Channel backed by the system LAContext.
func NewChannel() *Channel {
	return &Channel{eval: laCGoEvaluator{}}
}
