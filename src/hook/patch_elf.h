#pragma once

bool install_got_hook(const char* symbol_name, void* hook_fn, void** original_out);
