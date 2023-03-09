CPPFLAGS += -MMD -MP -MF $*.d
CFLAGS ?= -O2 -march=native

CP_AL = cp -al
MKDIR_P = mkdir -p

shared_sources = $(wildcard *.c *.h *.in)
#opt_sources = $(wildcard opt/*.c opt/*.h)
ref_sources = $(shared_sources) $(wildcard ref/*.c ref/*.h)
avx2_sources = $(shared_sources) $(wildcard avx2/*.c avx2/*.h)

all:
.PHONY: all

security_params = 128 192 256
taus_128 = 10 11 12 13 14 15 16 17 18 19 20 22 24 26 28 30 32 36 40 44
taus_192 = 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 32 34 36 38 40 42 44 46 48 52 56 60 64
taus_256 = 20 22 24 26 28 30 32 34 36 38 40 44 48 52 56 60 64 72 80 88

# Format: long name (for macro definition), single letter name.
ciphers = AES_CTR,c RIJNDAEL_EVEN_MANSOUR,e
tree_prgs = $(ciphers) SHA3,s

comma=,
define first
$(firstword $(subst $(comma), ,$(1)))
endef
define second
$(word 2,$(subst $(comma), ,$(1)))
endef

# Format: name,security_param,owf,prg,tree_prg,tau
settings = \
	$(foreach security_param,$(security_params),\
		$(foreach owf,$(ciphers),\
			$(foreach prg,$(ciphers),\
				$(foreach tree_prg,$(tree_prgs),\
					$(foreach tau,$(taus_$(security_param)),\
						sec$(security_param)_$(call second,$(owf))$(call second,$(prg))$(call second,$(tree_prg))_$(tau),$(security_param),$(call first,$(owf)),$(call first,$(prg)),$(call first,$(tree_prg)),$(tau)\
					)\
				)\
			)\
		)\
	)

define link-recipe
$(1)/$(2) : $(2) | $(dir $(1)/$(2))
	rm -f $$@
	$(CP_AL) $$< $$@
endef

define config-recipe
$(1)/% : %.in | $(1)/
	$(let name security_param owf prg tree_prg tau,$(subst $(comma), ,$(2)),\
	sed $(foreach substitution,"%VERSION%/$(name)" "%SECURITY_PARAM%/$(security_param)" "%OWF%/$(owf)" "%PRG%/$(prg)" "%TREE_PRG%/$(tree_prg)" "%TAU%/$(tau)",\
		-e "s/"$(substitution)"/g" \
	) $$< > $$@ \
	)
endef

define full-recipe
$(2)_objects = $$(patsubst %.c,$(3)/%.o,$$(filter %.c,$$($(1)_sources)))
$(2)_headers = $$(addprefix $(3)/,$$(filter %.h,$$(patsubst %.in,%,$$($(1)_sources))))
$(2)_targets = $$($(2)_objects) $$($(2)_headers)
$(2)_depfiles = $$(patsubst %.o,%.d,$$($(2)_objects))

$$(foreach src,$$($(1)_sources),$$(eval $$(call link-recipe,$(3),$$(src))))

$(eval $(call config-recipe,$(3),$(4)))

headers-$(2) : $$($(2)_headers)
.PHONY: headers-$(2)
$$($(2)_objects)) : headers-$(2)

$(3)/:
	$$(MKDIR_P) $$@
$(3)/%/:
	$$(MKDIR_P) $$@

all : $$($(2)_objects)

# https://make.mad-scientist.net/papers/advanced-auto-dependency-generation/
$$($(2)_depfiles):
include $$(wildecard $$($(2)_depfiles))
endef

$(foreach setting,$(settings),\
	$(let name,$(call first,$(setting)),\
		$(eval $(call full-recipe,ref,$(name)_ref,Reference_Implementations/$(name),$(setting)))\
	)\
)
$(foreach setting,$(settings),\
	$(let name,$(call first,$(setting)),\
		$(eval $(call full-recipe,avx2,$(name)_avx2,Additional_Implementations/$(name)_avx2,$(setting)))\
	)\
)
