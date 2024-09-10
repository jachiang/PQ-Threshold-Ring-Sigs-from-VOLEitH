COMMON_LD_FLAGS ?= -O2 -march=native -mtune=native -DNDEBUG # Benchmark
#COMMON_LD_FLAGS ?= -O2 -march=native -mtune=native -ggdb -fsanitize=address # Debug Fast
# COMMON_LD_FLAGS ?= -O0 -march=native -mtune=native -ggdb -fsanitize=address -fsanitize=undefined # Debug Slow
COMMON_CC_FLAGS ?= -pedantic-errors -Wall -Wextra -Wno-ignored-attributes $(COMMON_LD_FLAGS)

CFLAGS ?= -std=c11 $(COMMON_CC_FLAGS)
CXXFLAGS ?= -std=c++20 $(COMMON_CC_FLAGS)
LDFLAGS += -lcrypto $(COMMON_LD_FLAGS)

CP_L ?= cp -l
MKDIR_P ?= mkdir -p

ORIG_CPPFLAGS := $(CPPFLAGS)
CPPFLAGS = $(ORIG_CPPFLAGS) -MMD -MP -MF $*.d

export COMMON_LD_FLAGS COMMON_CC_FLAGS CFLAGS ORIG_CPPFLAGS CXXFLAGS LDFLAGS CP_L MKDIR_P

common_headers = Catch2/extras/catch_amalgamated.hpp
common_sources = $(common_headers) Catch2/extras/catch_amalgamated.cpp

submission_versions = sec128_cccs_11_0_pprf sec128_cccs_16_0_pprf sec192_cccs_16_0_pprf sec192_cccs_24_0_pprf sec256_cccs_22_0_pprf sec256_cccs_32_0_pprf sec128_eccs_11_0_pprf sec128_eccs_16_0_pprf sec192_eccs_16_0_pprf sec192_eccs_24_0_pprf sec256_eccs_22_0_pprf sec256_eccs_32_0_pprf

security_params = 128 192 256
archs = avx2

# Default settings to build with `make all`. Other settings are allowed.
taus_128 = 11 16
taus_192 = 16 24
taus_256 = 22 32
seeds_thresholds_128 = pprf 98 # If pprf, use old non-batch vector commitments.
seeds_thresholds_192 = pprf 147
seeds_thresholds_256 = pprf 196
owfs = c e r3 r4 mq1 mq8
prgs = c
tree_prgs = c
leaf_prgs = c s

zero_bit_counts = 0 6

default_settings := \
	$(foreach security_param,$(security_params),\
		$(foreach owf,$(owfs),\
			$(foreach prg,$(prgs),\
				$(foreach tree_prg,$(tree_prgs),\
					$(foreach leaf_prg,$(leaf_prgs),\
						$(if $(and $(findstring 192,$(security_param)),$(findstring e,$(prg)$(tree_prg)$(leaf_prg))),,\
							$(foreach tau,$(taus_$(security_param)),\
								$(foreach zero_bits,$(zero_bit_counts),\
									$(foreach seeds_threshold,$(seeds_thresholds_$(security_param)),\
										$(foreach arch,$(archs),\
											sec$(security_param)_$(owf)$(prg)$(tree_prg)$(leaf_prg)_$(tau)_$(zero_bits)_$(seeds_threshold)_$(arch)\
										)\
									)\
								)\
							)\
						)\
					)\
				)\
			)\
		)\
	)

default: $(default_settings)
.PHONY: default

all: $(addprefix all-,$(default_settings))
.PHONY: all

define link-recipe
$(1)/$(notdir $(2)) : $(3) | $(dir $(1)/$(notdir $(2)))
	rm -f $$@
	$(CP_L) $$< $$@
endef

# Compile common object files in a subfolder
common_objects := $(foreach obj,$(patsubst %.cpp,%.o,$(filter %.cpp,$(common_sources))),Common/$(notdir $(obj)))
$(foreach src,$(common_sources),$(eval $(call link-recipe,Common,$(src),$(src))))

export common_headers
export common_objects

headers-common : $(foreach header,$(common_headers),Common/$(notdir $(header)))
.PHONY: headers-common
$(common_objects) : | headers-common

Common/:
	$(MKDIR_P) $@

# - arguments:
#   $(1): architecture (e.g. "ref", "avx2")
#   $(2): security_param: security parameter (e.g. 128)
# 	$(3): subdirectory (e.g. "Additional_Implementations")
# 	$(4): target for recursive make.
define recursion-recipe
$(4)-sec$(2)_%_$(1): $(common_objects)
	$$(eval VARIANT := sec$(2)_$$*_$(1))
	@echo Making $(4) for $$(VARIANT)
	@`python3 scripts/parse_variant_name.py $$(VARIANT)` && $(MAKE) --no-print-directory -f Makefile.variant VARIANT=$$(VARIANT) SUBDIR=$(3)/$$(VARIANT) $(4)
	@rm -f $$@
endef
define recursion-alias-default-recipe
sec$(2)_%_$(1): default-sec$(2)_%_$(1)
	@rm -f $$@
endef
# Unfortunately, wildcard rules cannot be .PHONY, so if a file of the same name gets created then it
# might not work.

targets = all default
$(foreach security_param,$(security_params),\
	$(foreach arch,$(archs),\
		$(foreach target,$(targets),\
			$(eval $(call recursion-recipe,$(arch),$(security_param),Additional_Implementations,$(target)))\
		)\
		$(eval $(call recursion-alias-default-recipe,$(arch),$(security_param),Additional_Implementations))\
	)\
)

dist: $(foreach version,$(submission_versions),$(version)_avx2)
	rm -rf Submission
	$(foreach version,$(submission_versions),\
		$(foreach faest_name,$(shell python3 scripts/get_faest_name.py $(version)),\
			$(MKDIR_P) Submission/$(faest_name) &&\
			$(CP_L) Additional_Implementations/$(version)_avx2/*.{c,h,inc,macros,s} Additional_Implementations/$(version)_avx2/Makefile Submission/$(faest_name)/ &&\
		)\
	) true

.PHONY: dist

clean:
	rm -rf Reference_Implementation Additional_Implementations Common
.PHONY: clean
