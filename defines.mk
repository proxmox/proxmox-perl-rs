define package_template
	sed -r \
	  -e 's/\{\{PRODUCT\}\}/$(1)/g;' \
	  -e 's/\{\{LIBRARY\}\}/$(2)/g;' \
	  -e 's|\{\{DEBUG_LIBPATH\}\}|$(DEBUG_LIBPATH)|g;' \
	  Proxmox/Lib/template.pm \
	  >Proxmox/Lib/$(1).pm
endef
