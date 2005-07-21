use Module::Build;
Module::Build->new(
                   module_name => 'Net::IP::Match::Regexp',
                   license => 'perl',
                   requires => {
                      perl => "5.6.0",
                   },
                   build_requires => {
                      'Test::More'               => 0,
                   },
                   )->create_build_script;
