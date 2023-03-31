CPPFLAGS += -MMD -MP -MF $*.d
CFLAGS ?= -std=c11 -pedantic-errors -O2 -march=native -mtune=native

CP_L = cp -l
MKDIR_P = mkdir -p

keccak_sources = \
	$(wildcard XKCP/lib/high/Keccak/FIPS202/KeccakHash.*)\
	$(wildcard XKCP/lib/high/Keccak/KeccakSponge.*)\
	$(wildcard XKCP/lib/common/*)\
	$(wildcard XKCP/lib/low/common/*)\
	$(wildcard XKCP/lib/low/KeccakP-1600/common/*)
keccak_avx2_sources = \
	$(wildcard XKCP/lib/low/KeccakP-1600/AVX2/*)\
	$(wildcard XKCP/lib/low/KeccakP-1600-times2/SIMD128/KeccakP-1600-times2-*)\
	$(wildcard XKCP/lib/low/KeccakP-1600-times2/SIMD128/SSSE3-u2/SIMD128-config.h)\
	$(wildcard XKCP/lib/low/KeccakP-1600-times4/AVX2/KeccakP-1600-times4-*)\
	$(wildcard XKCP/lib/low/KeccakP-1600-times4/AVX2/u12/SIMD256-config.h)\
	$(wildcard XKCP/lib/low/KeccakP-1600-times8/fallback-on4/*)

shared_sources = $(wildcard *.c *.h *.in) $(keccak_sources)
#opt_sources = $(wildcard opt/*.c opt/*.h)
ref_sources = $(shared_sources) $(wildcard ref/*.c ref/*.h)
avx2_sources = $(shared_sources) $(wildcard avx2/*.c avx2/*.h) $(keccak_avx2_sources)
avx2_vaes_sources = $(shared_sources) $(wildcard avx2_vaes/*.c avx2_vaes/*.h) $(keccak_avx2_sources)

all:
.PHONY: all

security_params = 128 192 256
taus_128 = 10 11 12 13 14 15 16 17 18 19 20 22 24 26 28 30 32
taus_192 = 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 32 34 36 38 40 42 44 46 48
taus_256 = 20 22 24 26 28 30 32 34 36 38 40 44 48 52 56 60 64

# Format: long name (for macro definition), single letter name.
ciphers = AES_CTR,c RIJNDAEL_EVEN_MANSOUR,e
tree_prgs = $(ciphers)
leaf_prgs = $(ciphers)
# TODO: Add back RO,s

comma=,
define first
$(firstword $(subst $(comma), ,$(1)))
endef
define second
$(word 2,$(subst $(comma), ,$(1)))
endef

# Format: name,security_param,owf,prg,tree_prg,leaf_prg,tau
settings = \
	$(foreach security_param,$(security_params),\
		$(foreach owf,$(ciphers),\
			$(foreach prg,$(ciphers),\
				$(foreach tree_prg,$(tree_prgs),\
					$(foreach leaf_prg,$(leaf_prgs),\
						$(foreach tau,$(taus_$(security_param)),\
							$(if $(and $(findstring 192,$(security_param)),$(findstring RIJNDAEL,$(prg)$(tree_prg)$(leaf_prg))),,\
								sec$(security_param)_$(call second,$(owf))$(call second,$(prg))$(call second,$(tree_prg))$(call second,$(leaf_prg))_$(tau),$(security_param),$(call first,$(owf)),$(call first,$(prg)),$(call first,$(tree_prg)),$(call first,$(leaf_prg)),$(tau)\
							)\
						)\
					)\
				)\
			)\
		)\
	)

define link-recipe
$(1)/$(notdir $(2)) : $(2) | $(dir $(1)/$(notdir $(2)))
	rm -f $$@
	$(CP_L) $$< $$@
endef

define config-recipe
$(1)/% : %.in | $(1)/
	$(let name security_param owf prg tree_prg leaf_prg tau,$(subst $(comma), ,$(2)),\
	sed $(foreach substitution,"%VERSION%/$(name)" "%SECURITY_PARAM%/$(security_param)" "%OWF%/$(owf)" "%PRG%/$(prg)" "%TREE_PRG%/$(tree_prg)" "%LEAF_PRG%/$(leaf_prg)" "%TAU%/$(tau)",\
		-e "s/"$(substitution)"/g" \
	) $$< > $$@ \
	)
endef

define full-recipe
$(2)_objects = $$(foreach source,$$(patsubst %.c,%.o,$$(filter %.c,$$($(1)_sources))),$(3)/$$(notdir $$(source)))
$(2)_asm_objects = $$(foreach source,$$(patsubst %.s,%.o,$$(filter %.s,$$($(1)_sources))),$(3)/$$(notdir $$(source)))
$(2)_headers = $$(foreach header,$$(filter %.h %.inc %.macros,$$(patsubst %.in,%,$$($(1)_sources))),$(3)/$$(notdir $$(header)))
$(2)_targets = $$($(2)_objects) $$($(2)_asm_objects) $$($(2)_headers)
$(2)_depfiles = $$(patsubst %.o,%.d,$$($(2)_objects))

$$(foreach src,$$($(1)_sources),$$(eval $$(call link-recipe,$(3),$$(src))))

$(eval $(call config-recipe,$(3),$(4)))

headers-$(2) : $$($(2)_headers)
.PHONY: headers-$(2)
$$($(2)_objects)) : | headers-$(2)

$(3)/:
	$$(MKDIR_P) $$@
$(3)/%/:
	$$(MKDIR_P) $$@

$(2) : $$($(2)_targets)
.PHONY : $(2)
all : $(2)

# https://make.mad-scientist.net/papers/advanced-auto-dependency-generation/
$$($(2)_depfiles):
include $$(wildcard $$($(2)_depfiles))
endef

#$(foreach setting,$(settings),\
#	$(let name,$(call first,$(setting)),\
#		$(eval $(call full-recipe,ref,$(name)_ref,Reference_Implementation/$(name),$(setting)))\
#	)\
#)
$(foreach setting,$(settings),\
	$(let name,$(call first,$(setting)),\
		$(eval $(call full-recipe,avx2,$(name)_avx2,Additional_Implementations/$(name)_avx2,$(setting)))\
	)\
)
#$(foreach setting,$(settings),\
#	$(let name,$(call first,$(setting)),\
#		$(eval $(call full-recipe,avx2_vaes,$(name)_avx2_vaes,Additional_Implementations/$(name)_avx2_vaes,$(setting)))\
#	)\
#)
# TODO: AVX-512

clean:
	rm -rf Reference_Implementation Additional_Implementations
.PHONY: clean
