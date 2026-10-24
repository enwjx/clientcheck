#ifndef RDP_H
#define RDP_H

const char* rdp_scan(void);
/* Enable the 25-point RDP-ecosystem extended checklist (-rdp-extended).
 * Off by default: the heap-corruption workaround keeps it opt-in. */
void rdp_set_extended(int v);
/* Returns -1 if argv is not internal helper mode; otherwise a process exit code. */
int rdp_try_internal_helper(int argc, char** argv);

#endif
