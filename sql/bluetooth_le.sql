create table if not exists bluetooth_le
(
	address macaddr not null
		constraint bluetooth_le_pk
			primary key,
	name text,
	positions timestamp without time zone[],
	rssi integer,
	connectable boolean,
	advertisements text
);

create unique index if not exists bluetooth_le_address_uindex
	on bluetooth_le (address);

