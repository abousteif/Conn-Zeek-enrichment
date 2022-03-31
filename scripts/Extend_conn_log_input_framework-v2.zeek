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
# Add additional conn fields based on input framework
#Extending the conn.log - adding the following field to the record (conn info is what is logged)
redef record Conn::Info += {
	Reputation: Val &log &optional;
};

#The event that will be used to observe all the connections
event connection_state_remove(c: connection)
{
	if ( c$id$resp_h in Connenrichment_table ){
		c$conn$Reputation=Connenrichment_table[c$id$resp_h];
	}
}
