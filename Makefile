formats := gv html svg png

combined_model_name = main
# TODO can we programmatically build dependencies based on Include directives?
model_names := ${combined_model_name} caching toolchain packages publishing
model_deps := components.tml data.tml
combined_model_deps := $(foreach name,${model_names},${name}.tml) ${model_deps} clusters.tml

common_args := -v --combine --no-numbers --cluster-attrs color=Crimson fillcolor=white --edge-attrs color=black --wrap-labels 12

output := $(foreach format,${formats},$(foreach name,${model_names},${format}/${name}.${format}))


all: ${formats}
help:
	# TODO
clean:
	@for f in ${formats}; do rm -ri $${f}; done


model_files = $(foreach format,${formats},$(filter-out ${format}/${combined_model_name}.${format},${output}))
${model_files}: active = --active
${model_files}: ${model_deps}
combined_files = $(foreach format,${formats},${format}/${combined_model_name}.${format})
${combined_files}: ${combined_model_deps}

define create_rule

ifneq ($1,html)
$1: diagram = --diagram $1
endif

$1: $2
$2: $1/%.$1: %.tml
	@echo "Making $$@..."
	@mkdir -p $1
	@(dfdone ${common_args} --graph-attrs bgcolor=white $${active} $${diagram} $$< > $$@ && dfdone ${common_args} --graph-attrs bgcolor=white layout=neato overlap=false splines=true $${active} $${diagram} $$< > $$(subst .$1,_relationships.$1,$$@)) || rmdir --ignore-fail-on-non-empty $1

endef

$(eval $(foreach format,${formats},$(call create_rule,${format},$(foreach name,${model_names},${format}/${name}.${format}))))

