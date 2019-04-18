create table if not exists bluetooth_classic
(
	address macaddr not null
		constraint bluetooth_classic_pkey
			primary key,
	name text,
	positions timestamp without time zone[]
);

