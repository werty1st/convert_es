"use strict";

const fs = require('fs')
    , util = require('util')
    , stream = require('stream')
    , crypto = require('crypto')
    , es = require('event-stream')
    , jwt = require('jsonwebtoken')
    , Gauge = require("gauge")
    , readline = require('readline')
    , exec = require('child_process').exec;

/**
 * elasticdump --input=http://localhost:9200/filebeat --output=export.json --type=data --searchBody '{"query": { "match_all": {}}, "stored_fields": ["*"], "_source": false}' --limit 10000
 * node --max_old_space_size=400 node_modules/.bin/elasticdump --input=http://localhost:9200/filebeat --output=$ --type=data --searchBody '{"query": { "match_all": {}}, "stored_fields": ["*"], "_source": true}' --limit 100 | node --max_old_space_size=40 removeInfo.js  --infile=- --outfile=out.js --overwrite
 */

const argv = require('minimist')(process.argv.slice(2));

let s; //input stream
let outfile = 'myOutput.json';
let infile  = '20170321_filebeat_1000.json';
let overwrite = false;
let linecount = 1; //count processed lines
let skipcount = 0; //count ignored lines
let maxlines = 0;  //try to get max lines of infile

// parse process.argv
    function printusage () {

            console.error("Usage: node removeInfo.js [options] arguments");
            console.error("Options:");
            console.error("\t--overwrite\toverwrites outfile if present");
            console.error("Arguments:");
            console.error("\t-i, --infile  = [filename|-]\tfilename to read from or - to read from stdin");
            console.error("\t-o, --outfile = [filename]\tfile to save output data to");
            process.exit();
    }
    if ( infile = (argv.i || argv.infile) ){
        if ( infile == "-"){
            //read from stdin
            s = process.stdin;
            maxlines = 1;
        } else if ( !fs.existsSync(infile)) {
            console.error("Error:");
            console.error("\tInput File not found.");
            printusage();
        } else {
            //normal input file
            s = fs.createReadStream(infile);
            //file found: count lines
            exec('wc -l ' + infile, (error, stdout, stderr) => {
            if (error) {
                return;
            }
            maxlines = stdout.split(" ")[0];
            });            
        }      
    } else {
            console.error("Error:");
            console.error("\tInput File not defined.");
            printusage();    
    }

    if ( outfile = (argv.o || argv.outfile) ){

        if (!( overwrite = argv.overwrite )){
            if ( fs.existsSync(outfile)) {
                console.error("Error: Won't overwrite existing File. Delete it first.");
                printusage();
            } 
        }

       
    } else {
            console.error("Error:")
            console.error("\tOutput File not defined.")
            printusage();    
    }



const wstream = fs.createWriteStream(outfile);
const gauge = new Gauge({ updateInterval: 100, theme: "brailleSpinner" });
gauge.show("Counting lines");

s.pipe(es.split())
 .pipe(es.mapSync(function(line){        

        // pause the readstream
        s.pause();

        // process line here and call s.resume() when rdy
        try{
            let line2 = removeInfo( JSON.parse(line) );
            
            linecount += 1;
            
            if (maxlines>0){
                gauge.pulse( linecount );
                gauge.show("Skipped: " + skipcount + " - Processed", linecount / maxlines );
            }

            //hash user ID with MD5
            line2.user = crypto.createHash('md5').update(line2.user).digest("hex");
            wstream.write( JSON.stringify(line2)+'\n');
        } catch (e) {
            //ignore empty line at end
            if ( e.message.indexOf("Unexpected end of input") ){
                //console.log("SKIPPIGN error",e);
                //process.exit();
                skipcount += 1;
            }
        }

        // resume the readstream, possibly from a callback
        s.resume();
    })
    .on('error', function(){
        console.log('Error while reading file.');
        gauge.hide(()=>{
            wstream.end();
        });
    })
    .on('end', function(){
        
        gauge.pulse("Done");
        gauge.hide(()=>{
            wstream.end();
        });
        console.log('Done.');
        
    })
);



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