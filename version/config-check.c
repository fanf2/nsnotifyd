#define BIND_8_COMPAT

#include <resolv.h>

#if __RES != 20090302
#error incompatible resolver
#endif

int main(void) {
	res_init();
}
