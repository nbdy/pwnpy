create table if not exists positions
(
	longitude double precision not null,
	latitude double precision not null,
	altitude double precision not null,
	speed double precision not null,
	time timestamp not null
);

