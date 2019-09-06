@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

redef Intel::read_files += {
      fmt("%s/otx.dat", @DIR)
};
