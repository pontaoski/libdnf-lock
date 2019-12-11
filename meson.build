project('libdnf-lock', 'cpp')

lock_deps = [dependency('libdnf')]

lock_sources = [
    'src/lock.cpp',
]

lock_lib = shared_library('lock',
                          lock_sources,
                          dependencies: lock_deps,
                          install: true,
                          install_dir: join_paths(get_option('libdir'),
                                                  'libdnf',
                                                  'plugins')
                         )