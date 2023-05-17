#COMMON_LD_FLAGS ?= -O2 -march=native -mtune=native # Benchmark
#COMMON_LD_FLAGS ?= -O2 -march=native -mtune=native -ggdb -fsanitize=address # Debug Fast
COMMON_LD_FLAGS ?= -Og -march=native -mtune=native -ggdb -fsanitize=address -fsanitize=undefined # Debug Slow
COMMON_CC_FLAGS ?= -pedantic-errors -Wall -Wextra -Wno-ignored-attributes $(COMMON_LD_FLAGS)

CPPFLAGS += -MMD -MP -MF $*.d
CFLAGS ?= -std=c11 $(COMMON_CC_FLAGS)
CXXFLAGS ?= -std=c++14 $(COMMON_CC_FLAGS)
LDFLAGS += -lcrypto $(COMMON_LD_FLAGS)

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
common_headers = Catch2/extras/catch_amalgamated.hpp
common_sources = $(common_headers) Catch2/extras/catch_amalgamated.cpp

shared_sources = $(wildcard *.c *.h *.in) $(keccak_sources)
#opt_sources = $(wildcard opt/*.c opt/*.h)
ref_sources = $(shared_sources) $(wildcard ref/*.c ref/*.h)
avx2_sources = $(shared_sources) $(wildcard avx2/*.c avx2/*.h) $(keccak_avx2_sources)
avx2_vaes_sources = $(shared_sources) $(wildcard avx2_vaes/*.c avx2_vaes/*.h) $(keccak_avx2_sources)
test_sources = $(wildcard test/*.cpp test/*.hpp) $(common_headers)

all:
.PHONY: all

security_params = 128 192 256
#taus_128 = 10 11 12 13 14 15 16 17 18 19 20 22 24 26 28 30 32
#taus_192 = 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 32 34 36 38 40 42 44 46 48
#taus_256 = 20 22 24 26 28 30 32 34 36 38 40 44 48 52 56 60 64
taus_128 = 10 16 32
taus_192 = 15 24 48
taus_256 = 20 32 64

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
	$(let iv_bits,$(if $(findstring RIJNDAEL,$(owf)),$(security_param),128),\
	$(let sk_bytes,$(shell expr "(" $(security_param) "+" $(iv_bits) ")" "/" 8),\
	$(let pk_bytes,$(if $(and $(findstring AES_CTR,$(owf)),$(intcmp $(security_param),192)),48,$(sk_bytes)),\
	sed $(foreach substitution,\
		"%VERSION%/$(name)"\
		"%SECURITY_PARAM%/$(security_param)"\
		"%OWF%/$(owf)"\
		"%PRG%/$(prg)"\
		"%TREE_PRG%/$(tree_prg)"\
		"%LEAF_PRG%/$(leaf_prg)"
		"%TAU%/$(tau)"
		"%SECRETKEYBYTES%/$(sk_bytes)"\
		"%PUBLICKEYBYTES%/$(pk_bytes)",\
		-e "s/"$(substitution)"/g" \
	) $$< > $$@ \
	))))
endef


# canned recipe for a variant
# - arguments:
# 	$(1): architecture (e.g. "ref", "avx2")
# 	$(2): setting name (e.g. "sec128_cccc_10_avx2")
# 	$(3): path (e.g. "Additional_Implementations/sec128_cccc_10_avx2")
# 	$(4): setting (comma-separated list of the form name,security_param,owf,prg,tree_prg,leaf_prg,tau)
define full-recipe

# $(1)_sources contains the shared and archtecture-specific source files

$(2)_objects = $$(foreach source,$$(patsubst %.c,%.o,$$(filter %.c,$$($(1)_sources))),$(3)/$$(notdir $$(source)))
$(2)_asm_objects = $$(foreach obj,$$(patsubst %.s,%.o,$$(filter %.s,$$($(1)_sources))),$(3)/$$(notdir $$(obj)))
$(2)_headers = $$(foreach header,$$(filter %.h %.inc %.macros,$$(patsubst %.in,%,$$($(1)_sources))),$(3)/$$(notdir $$(header)))
$(2)_test_headers = $$(foreach header,$$(filter %.hpp,$$(test_sources)),$(3)/$$(notdir $$(header)))
$(2)_test_objects = $$(foreach obj,$$(patsubst %.cpp,%.o,$$(filter %.cpp,$$(test_sources))) $$(common_objects),$(3)/$$(notdir $$(obj)))
$(2)_targets = $$($(2)_objects) $$($(2)_asm_objects) $$($(2)_headers) $$($(2)_test_objects) $(3)/$(2)_test
$(2)_depfiles = $$(patsubst %.o,%.d,$$($(2)_objects)) $$(patsubst %.o,%.d,$$($(2)_test_objects))

# hard link all source files into the variant directory. Also copy common object files.
$$(foreach src,$$($(1)_sources) $$(test_sources) $$(common_objects),$$(eval $$(call link-recipe,$(3),$$(src))))

# generate config.h with the setting-specific constants
$(eval $(call config-recipe,$(3),$(4)))

# object files depend on the headers (build order only)
headers-$(2) : $$($(2)_headers)
.PHONY: headers-$(2)
$$($(2)_objects)) : | headers-$(2)

# same for test files
test-headers-$(2) : $$($(2)_test_headers)
.PHONY: test-headers-$(2)
$$($(2)_test_objects)) : | headers-$(2) test-headers-$(2)

# target for test binary
$(3)/$(2)_test : $$($(2)_test_objects) $$($(2)_objects) $$($(2)_asm_objects)
	$(CXX) -o $$@ $(LDFLAGS) $$^ $(LOADLIBES) $(LDLIBS)

# targets to create (sub)directories
$(3)/:
	$$(MKDIR_P) $$@
$(3)/%/:
	$$(MKDIR_P) $$@

# target for the variant directory
$(2) : $$($(2)_targets)
.PHONY : $(2)
all : $(2)

# magic to generate dependency files
# https://make.mad-scientist.net/papers/advanced-auto-dependency-generation/
$$($(2)_depfiles):
include $$(wildcard $$($(2)_depfiles))
endef

# Compile common object files in a subfolder
common_objects = $(foreach obj,$(patsubst %.cpp,%.o,$(filter %.cpp,$(common_sources))),Common/$(notdir $(obj)))
$(foreach src,$(common_sources),$(eval $(call link-recipe,Common,$(src))))

headers-common : $(foreach header,$(common_headers),Common/$(notdir $(header)))
.PHONY: headers-common
$(common_objects) : | headers-common

Common/:
	$(MKDIR_P) $@

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
	rm -rf Reference_Implementation Additional_Implementations Common
.PHONY: clean
