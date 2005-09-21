use Module::Build;
Module::Build->new(
   module_name => 'Net::IP::Match::Regexp',
   dist_author => 'Clotho Advanced Media, Inc. <cpan@clotho.com>',
   license => 'perl',
   requires => {
      perl => "5.6.0",
   },
   build_requires => {
      'Test::More' => 0,
   },
   add_to_cleanup => [ 'Net-IP-Match-Regexp-*' ],
)->create_build_script;
