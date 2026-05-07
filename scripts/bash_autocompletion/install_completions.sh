#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright © 2025 Intel Corporation
# Author: Jan Sokolowski <jan.sokolowski@intel.com>

usage() {
echo "install_completions.sh - creates bash autocompletion scripts for installed igt gpu tools tests."
echo "Usage: "
echo "--install : installs completions for installed /usr/local/libexec/igt_gpu_tools tests to ~/.local/share/bash-completion/completions"
echo "--local-install : uses ../../build/tests as list of completions to install to ~/.local/share/bash-completion/completions"
echo "--uninstall : uninstalls completions installed to /usrl/local/libexec/igt_gpu_tools from ~/.local/share/bash-completion/completions"
echo "--local-uninstall : uses ../../build/tests as list of completions to uninstall from ~/.local/share/bash-completion-completions"
}

__generate_completion() {

cat <<EOF > $1
_$1()
{
	local cur prev words cword
	_init_completion || return
	case \$prev in
		--run-subtest | --dynamic-subtest)
			local IFS=$'\n\b'
			LIST_OF_TESTS="\`\$1 --list-subtest\`"
			COMPREPLY=(\$(compgen -W "\$LIST_OF_TESTS" -- "\$cur"))
			return
			;;
		--device)
			COMPREPLY=(\$(compgen -o nospace -W "sys: pci: sriov: drm:" -- "\$cur"))
			;;
	esac

	if [[ \$cur == * ]]; then
		COMPREPLY=(\$(compgen -W '\$(_parse_help "\$1")' -- "\$cur"))
	fi

} &&

complete -F _$1 $1
EOF

}

__install_completions() {
	mkdir -p ~/.local/share/bash-completion/completions
	cd ~/.local/share/bash-completion/completions

	echo "Installing bash autocompletion scripts to ~/.local/share/bash_completion/completions"
	for ENTRY in `sed -n 2p $1/test-list-full.txt`;
	do
		TEST=`echo $ENTRY | rev | cut -f1 -d'/' | rev`
		__generate_completion $TEST
	done
	cd - > /dev/null
}

__uninstall_completions() {
	cd ~/.local/share/bash-completion/completions
	echo "Unnstalling bash autocompletion scripts from ~/.local/share/bash_completion/completions"
	for ENTRY in `sed -n 2p $1/test-list-full.txt`;
	do
		TEST=`echo $ENTRY | rev | cut -f1 -d'/' | rev`
		rm -f ~/.local/share/bash-completion/completions/$TEST
	done
	cd - > /dev/null
}

case "$1" in
	"--install")
		__install_completions "/usr/local/libexec/igt-gpu-tools"
		;;
	"--local-install")
		__install_completions "$PWD/build/tests"
		;;
	"--uninstall")
		__uninstall_completions "/usr/local/libexec/igt-gpu-tools"
		;;
	"--local-uninstall")
		__uninstall_completions "$PWD/build/tests"
		;;
	"--help")
		usage
		;;
	*)
		__install_completions "/usr/local/libexec/igt-gpu-tools"
		;;
esac
