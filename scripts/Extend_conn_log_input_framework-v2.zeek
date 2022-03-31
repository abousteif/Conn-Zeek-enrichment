module MyConnEnrichment;

# Add additional conn fields based on input framework
#Extending the conn.log - adding the following field to the record (conn info is what is logged)
redef record Conn::Info += {
	enrichment_resp:	Val	&log	&optional;
};

#The event that will be used to observe all the connections
event connection_state_remove(c: connection)
{
	if ( c$id$resp_h in connenrichment_table ){
		c$conn$enrichment_resp=connenrichment_table[c$id$resp_h];
	}
}
