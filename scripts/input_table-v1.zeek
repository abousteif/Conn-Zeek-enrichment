module MyConnEnrichment;

type Idx: record {
        ip: addr;
};

type Val: record {
        enrichment: string &log;
};

global Connenrichment_table: table[addr] of Val = table();

event zeek_init()
{
    Input::add_table([
        $source="Connenrichment.csv",
        $name="Connenrichment_table",
        $idx=Idx,
        $val=Val,
        $destination=Connenrichment_table,
        $mode=Input::REREAD
    ]);
}
