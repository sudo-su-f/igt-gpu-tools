panthor_progs = [
	'panthor_query'
]

foreach prog : panthor_progs
	test_executables += executable(prog, prog + '.c',
				       dependencies : test_deps,
				       install_dir : panthordir,
				       install_rpath : panthor_rpathdir,
				       install : true)
	test_list += join_paths('panthor', prog)
endforeach
