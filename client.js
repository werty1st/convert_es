"use strict";


const fs = require('fs')
	, net = require('net')
    , util = require('util')
    , stream = require('stream')
    , crypto = require('crypto')
    , es = require('event-stream')
    , jwt = require('jsonwebtoken');



const server = net.createServer(function(socket) {


	socket.pipe(es.split())
	 .pipe(es.mapSync(function(line){        


	        // process line here and call s.resume() when rdy
	        try{
	            let line2 = removeInfo( JSON.parse(line) );	            
	            
	            //hash user ID with MD5
	            line2.user = crypto.createHash('md5').update(line2.user).digest("hex");
	            socket.write(JSON.stringify(line2)+'\n');

	        } catch (e) {
	            //ignore empty line at end
	            if ( e.message.indexOf("Unexpected end of input") ){
	                console.log("error",e);
	                process.exit();
	            }
	        }

	    })
	);

});

server.listen(5000, '127.0.0.1');







function removeInfo(line){

    
    // move line.source to line
    line = line._source;

    // remove all unwanted data

    delete line["@timestamp"];
    delete line["@version"];
    delete line["auth"];
    delete line["beat"];
    delete line["bytes"];
    delete line["clientip"];
    delete line["count"];
    delete line["fields"];
    delete line["host"];
    delete line["httpversion"];
    delete line["ident"];
    delete line["input_type"];
    delete line["offset"];

    delete line["received_from"];
    delete line["referrer"];
    delete line["request"];
    delete line["response"];
    delete line["source"];

    delete line["start"];
    delete line["tags"];
    delete line["timestamp"];
    delete line["type"];
    delete line["uri_param"];
    delete line["verb"];

    if (line.token && (line.token != "false")){
        line.user = jwt.decode(line.token).id;
        delete line["token"];
    }

    return line;
}