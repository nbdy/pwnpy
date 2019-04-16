create table if not exists bluetooth_classic
(
	address macaddr not null
		constraint bluetooth_classic_pk
			primary key,
	name text,
	positions timestamp without time zone[]
);

create unique index if not exists bluetooth_classic_address_uindex
	on bluetooth_classic (address);

