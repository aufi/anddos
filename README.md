About ANDDOS
------------
Anti-DDOS module for nginx webserver. The aim is to restrict impact DDOS attacks to your webserver on HTTP level.

For more information visit https://github.com/aufi/anddos/wiki

***Under development***

Installation
------------

Install/compile anddos to nginx (development enviroment)

    $ cd src/nginx

    $ make clean && ./configure --add-module=../anddos/anddos && make -j2

    # make install
    or
    # /usr/local/nginx/sbin/nginx -s stop; make install && rm /usr/local/nginx/logs/* && /usr/local/nginx/sbin/nginx


Setup config files - nginx.conf

	location / {
		
	anddos;				#add this line to enable anddos

	proxy_pass         http://127.0.0.1:80;		#your app server
       	proxy_redirect     off;
		
       	proxy_set_header   Host             $host;
       	proxy_set_header   X-Real-IP        $remote_addr;
       	proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
       	proxy_max_temp_file_size 0;
    }

(Re)start nginx

    # /usr/local/nginx/sbin/nginx -s stop
    # /usr/local/nginx/sbin/nginx
    or
    # /usr/local/nginx/sbin/nginx -s reload

Author
------
Marek Aufart, aufi.cz@gmail.com, http://twitter.com/auficz
