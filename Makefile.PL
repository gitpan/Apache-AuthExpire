
    # ExtUtils::AutoInstall Bootstrap Code, version 7.
    BEGIN{my$p='ExtUtils::AutoInstall';my$v=0.52;$p->VERSION||0>=$v
    or+eval"use $p $v;1"or+do{my$e=$ENV{PERL_EXTUTILS_AUTOINSTALL};
    (!defined($e)||$e!~m/--(?:default|skip|testonly)/and-t STDIN or
    eval"use ExtUtils::MakeMaker;WriteMakefile(PREREQ_PM=>{'$p',$v}
    );1"and exit)and print"==> $p $v required. Install it from CP".
    "AN? [Y/n] "and<STDIN>!~/^n/i and print"*** Installing $p\n"and
    do{if (eval '$>' and lc(`sudo -V`) =~ /version/){system('sudo',
    $^X,"-MCPANPLUS","-e","CPANPLUS::install $p");eval"use $p $v;1"
    ||system('sudo', $^X, "-MCPAN", "-e", "CPAN::install $p")}eval{
    require CPANPLUS;CPANPLUS::install$p};eval"use $p $v;1"or eval{
    require CPAN;CPAN::install$p};eval"use $p $v;1"||die"*** Please
    manually install $p $v from cpan.org first...\n"}}}

    # optional pre-install handler; takes $module_name and $version
    # sub MY::preinstall  { return 1; }	# return false to skip install

    # optional post-install handler; takes $module_name, $version, $success
    # sub MY::postinstall { return; }	# the return value doesn't matter

    # the above handlers must be declared before the 'use' statement
    use ExtUtils::AutoInstall (
	-version	=> '0.40',	# required AutoInstall version
	                                # usually 0.40 is sufficient
	-config		=> {
	    make_args	=> '--hello',	# option(s) for CPAN::Config
	    force	=> 1,		# pseudo-option to force install
	    do_once	=> 1,		# skip previously failed modules
	},
	-core		=> 'all', 		# core modules; may also be 'all'
        'Feature1'	=> [
	    # do we want to install this feature by default?
	    -default	=> ( system('feature1 --version') == 0 ),
	    mod_perl	=> '',
	],
    );

    WriteMakefile(
	AUTHOR          => 'J. J. Horner jjhorner@bellsouth.net and Shannon Eric Peevey (speeves@erikin.com)',
	ABSTRACT        => 'Apache::AuthExpire -- Sets a time limit on the amount of time an authenticated connection to the web server will be allowed to remain inactive',
	NAME            => 'Apache::AuthExpire',
	VERSION_FROM    => 'AuthExpire.pm',
	DISTNAME        => 'Apache-AuthExpire',
    );
