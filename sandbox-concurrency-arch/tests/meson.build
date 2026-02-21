test_names = [
  'test_predicates',
  'test_pipe_alloc',
  'test_multi_output',
  'test_debugfs_guard',
  'test_combo_iterator',
  'test_full_examples',
]

foreach t : test_names
  exe = executable(t,
    t + '.c',
    dependencies : sandbox_dep,
  )
  test(t, exe, timeout : 30)
endforeach
