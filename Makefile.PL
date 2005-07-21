use ExtUtils::MakeMaker;
WriteMakefile(
              'NAME'		=> 'Net::IP::Match::Regexp',
              'VERSION_FROM'	=> 'lib/Net/IP/Match/Regexp.pm',
              'PREREQ_PM'	=> {
                 'Test::More'               => '0.01',
              },
              'PL_FILES'        => {},
              ($] >= 5.005 ?
               (ABSTRACT_FROM => 'lib/Net/IP/Match/Regexp.pm',
                AUTHOR     => 'Clotho Advanced Media Inc., <cpan@clotho.com>') : ()),
              );
