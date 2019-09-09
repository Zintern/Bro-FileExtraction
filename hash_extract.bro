@load base/frameworks/intel

event Intel::Match(s: Intel::Seen, items:set[Intel::Item])
{

                if(s$indicator_type == Intel::FILE_HASH)
                {
                Files::add_analyzer(s$f, Files::ANALYZER_EXTRACT);
                }

}
