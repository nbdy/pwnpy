create table if not exists wifi
(
	address macaddr not null
		constraint wifi_pkey
			primary key,
	device_type text not null,
	channel integer not null,
	encryption text not null,
	communication_partners text[],
	essid text,
	positions timestamp without time zone[],
	rates text
);

