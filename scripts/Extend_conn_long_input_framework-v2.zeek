module MyConnEnrichment;

# Add additional conn fields based on input framework
#Extending the conn.log - adding the following field to the record (conn info is what is logged)
redef record conn::Info += {
	enrichment_conn:	Val	&log	&optional;
};

#The event that will be used to observe all the connections
event connection_state_remove(c: connection)
{
	if ( c$id$orig_h in enrichment_table ){
		c$conn$enrichment_orig=enrichment_table[c$id$orig_h];
	}
}
