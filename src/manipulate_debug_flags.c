#include "internal/internal.h"
#include "swift_net.h"

void swiftnet_add_debug_flags(const SwiftNetDebugFlags flags) {
  debugger.flags |= flags;
}
void swiftnet_remove_debug_flags(const SwiftNetDebugFlags flags) {
  debugger.flags &= ~flags;
}
