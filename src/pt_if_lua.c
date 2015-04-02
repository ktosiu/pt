#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "pt_include.h"

luaL_Reg pt_if_lua_uc_lib[] = {
    {NULL, NULL}
};

int pt_if_lua_uc_open(lua_State *L) 
{
    luaL_newlib(L, pt_if_lua_uc_lib);
    return 1;
}

static const luaL_Reg pt_if_lua_libs[] = {
    {"pt_uc", pt_if_lua_uc_open},
    {NULL, NULL}
};

