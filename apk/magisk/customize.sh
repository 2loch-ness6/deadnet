#!/system/bin/sh
# DeadNet Magisk module install hook.
# Binaries are overlaid from this module's system/bin into /system/bin (systemless).
# We only need to make sure they are executable; Magisk handles the bind-mount.

ui_print "- DeadNet Tools: installing native engines"

set_perm_recursive "$MODPATH/system/bin" 0 0 0755 0755

# Report what shipped so the user sees it at flash time.
for t in deadnet-emit deadnet-sniff deadnet-synscan deadnet-arp deadnet-nra wpa_supplicant udhcpc; do
  if [ -f "$MODPATH/system/bin/$t" ]; then
    ui_print "    + $t"
  fi
done

ui_print "- Done. Reboot to activate (binaries appear in PATH as /system/bin/<name>)."
