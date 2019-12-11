#include <libdnf/libdnf.h>
#include <fstream>
#include <vector>

extern "C"
{
    const PluginInfo* pluginGetInfo(void);
    PluginHandle* pluginInitHandle(int version, PluginMode mode, DnfPluginInitData* initData);
    void pluginFreeHandle(PluginHandle* handle);
    int pluginHook(PluginHandle* handle, PluginHookId id, DnfPluginHookData* hookData, DnfPluginError* error);
}

static const PluginInfo info = {
    .name = "LibDnfLock",
    .version = "0.0"
};

const PluginInfo* pluginGetInfo(void) {
    return &info;
}

struct _PluginHandle
{
    PluginMode mode;
    DnfContext * context;  // store plugin context specific init data
    FILE * outStream; // stream to write output
};

const char* getHookName(PluginHookId id) {
    if (id == PLUGIN_HOOK_ID_CONTEXT_PRE_CONF) {
        return "Pre-Conf";
    } else if (id == PLUGIN_HOOK_ID_CONTEXT_CONF) {
        return "Conf";
    } else if (id == PLUGIN_HOOK_ID_CONTEXT_PRE_TRANSACTION) {
        return "Pre-Trans";
    } else if (id == PLUGIN_HOOK_ID_CONTEXT_TRANSACTION) {
        return "Trans";
    } else if (id == PLUGIN_HOOK_ID_CONTEXT_PRE_REPOS_RELOAD) {
        return "Pre-Reload";
    }
}

PluginHandle* pluginInitHandle(int version, PluginMode mode, DnfPluginInitData* initData) {
    PluginHandle* handle = NULL;
    FILE* outStream = fopen("/tmp/libdnflock.log", "a");
    if (!outStream)
        return handle;

    do {
        fprintf(outStream, "===\t< %s | %s >\tEnter\n", info.name, __func__);
        fprintf(outStream, "Plugin Version:\t%s\nAPI Version:\t%i\nMode:\t\t%i\n", info.version, version, mode);
        if (version != 1) {
            fprintf(outStream, "< %s | %s >\tError: Unsupported API Version\n", info.name, __func__);
            break;
        }
        if (mode != PLUGIN_MODE_CONTEXT) {
            fprintf(outStream, "< %s | %s >\tWarning: Unsupported mode.\n", info.name, __func__);
            break;
        }
        handle = (PluginHandle* ) malloc(sizeof(*handle));
        handle->mode = mode;
        handle->context = pluginGetContext(initData);
        handle->outStream = outStream;
    } while(0);

    fprintf(outStream, "===\t< %s | %s >\tExit\n\n\n", info.name, __func__);
    if (handle)
        fflush(outStream);
    else
        fclose(outStream);
    return handle;
}

void pluginFreeHandle(PluginHandle* handle) {
    if (handle) {
        fprintf(handle->outStream, "< %s | %s >\tClosing handle...\n", info.name, __func__);
        fclose(handle->outStream);
        free(handle);
    }
}

int pluginHook(PluginHandle* handle, PluginHookId id, DnfPluginHookData* hookData, DnfPluginError* error) {
    if (!handle)
        return 1;
    fprintf(handle->outStream, "===\t< %s | %s> [ID: %i]\tEnter\n", info.name, __func__, id);
    fflush(handle->outStream);
    if (id == PLUGIN_HOOK_ID_CONTEXT_TRANSACTION) {
        fprintf(handle->outStream, "Pre-Transaction Hook!\n\n");
        fflush(handle->outStream);
        DnfSack* sack = dnf_context_get_sack(handle->context);
        std::ifstream in("/etc/dnf/plugins/versionlock.list");
        std::string str;
        std::vector<std::string> strVect;
        while (std::getline(in, str))
        {
            if(str.size() > 0) {
                if (strncmp(str.c_str(), std::string("#").c_str(), std::string("#").size())) {
                    fprintf(handle->outStream, "lock %s!\n", str.c_str());
                    fflush(handle->outStream);
                    strVect.push_back(str);
                } else {
                    fprintf(handle->outStream, "\tnot %s!\n", str.c_str());
                    fflush(handle->outStream);
                }
            }
        }
        in.close();

        for (int i = 0; i < strVect.size(); i++) {
            fprintf(handle->outStream, "Querying for %s!\n", strVect[i].c_str());
            fflush(handle->outStream);
            HyQuery query = hy_query_create(sack);
            hy_query_is_empty(query);
            int result = hy_query_filter(query, HY_PKG_NAME, HY_GLOB, strVect[i].c_str());
            fprintf(handle->outStream, "Query result is %i!\n", result);
            fflush(handle->outStream);
            if (result == DNF_ERROR_BAD_QUERY) {
                fprintf(handle->outStream, "Bad query!\n");
                fflush(handle->outStream);
            } else {
                if (!hy_query_is_empty(query)) {
                    DnfPackageSet* pkgset = hy_query_run_set(query);
                    dnf_sack_add_excludes(sack, pkgset);
                } else {
                    fprintf(handle->outStream, "Lock query is empty!");
                    fflush(handle->outStream);
                }
            }
        }
    } else {
        fprintf(handle->outStream, "Not handling hook %s, because it's not %s!\n", getHookName(id), getHookName(PLUGIN_HOOK_ID_CONTEXT_TRANSACTION));
        fflush(handle->outStream);
    }
    fprintf(handle->outStream, "===\t< %s | %s> [ID: %i]\tExit\n\n\n", info.name, __func__, id);
    fflush(handle->outStream);
    return 1;
}