#include "getAttributes.h"
#include "setAttributes.h"

napi_value init_all(napi_env env, napi_value exports) {
	napi_value o;
	napi_create_string_latin1(env, "3.18.918", NAPI_AUTO_LENGTH, &o);
	napi_set_named_property(env, exports, "version", o);
	napi_set_named_property(env, exports, "getAttributes", getAttributes::init(env));
	napi_set_named_property(env, exports, "getAttributesSync", getAttributes::init(env, true));
	napi_set_named_property(env, exports, "setAttributes", setAttributes::init(env));
	napi_set_named_property(env, exports, "setAttributesSync", setAttributes::init(env, true));
	napi_create_object(env, &o);
	return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init_all)
