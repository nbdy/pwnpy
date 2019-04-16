create table if not exists wifi
(
	device_type integer,
	channel integer,
	encryption integer,
	communication_partners macaddr[],
	essid text
);

