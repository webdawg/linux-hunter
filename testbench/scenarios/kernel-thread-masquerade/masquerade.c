/* SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Testbench fixture, not part of hunter itself: renames this process to
 * look like a kernel worker thread, then sleeps so hunter has time to
 * observe it. A real kernel thread never reaches this check at all (it
 * has no /proc/<pid>/exe symlink); this is the one-line call an
 * attacker uses to make a userspace process with a real exe masquerade
 * as one in a `ps`/`top` listing anyway. See
 * src/checks/processes.rs's KERNEL_THREAD_NAME_PREFIXES check.
 */
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
    prctl(PR_SET_NAME, "kworker/0:1", 0, 0, 0);
    sleep(300);
    return 0;
}
