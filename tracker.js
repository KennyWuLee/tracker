const http = require('http');
const url = require('url');

const hostname = '127.0.0.1';
const port = 3000;

const interval = 60;

var data = {};

function decode(string) {
  var result = "";
  for(i = 0; i < string.length; i++) {
    var c = string.charAt(i);
    if(c == '%') {
      var hex = string.substring(i+1, i+3);
      result += String.fromCharCode("0x" + hex);
      i += 2;
    } else {
      result += c;
    }
  }
  return result;
}

function parseParameters(query) {
  var parameters = {};
  for(var s of query.split("&")) {
    var split = s.split("=");
    var key = decode(split[0]);
    var value = decode(split[1]);
    parameters[key] = value;
  }
  return parameters;
}

function addEntry(info_hash, peer_id, ip, port) {
  if(! data.hasOwnProperty(info_hash)) {
    data[info_hash] = {}
  }
  data[info_hash][peer_id] = { "type": "regular", "ip": ip, "port": port };
}

function addTorEntry(info_hash, peer_id, address) {
  if(! data.hasOwnProperty(info_hash)) {
    data[info_hash] = {}
  }
  data[info_hash][peer_id] = { "type": "tor", "address": address };
}

function encodePeerList(info_hash) {
  var result = "";
  result += "l";
    for(var peer in data[info_hash]) {
      if(data[info_hash].hasOwnProperty(peer)) {
        result += "d";
          result += "7:peer id";
            result += "20:" + peer;
          if(data[info_hash][peer].hasOwnProperty("address")) {
            result += "7:address"
              var adr = data[info_hash][peer].address;
              result += address.length + ":" + address;
          } else {
            result += "2:ip";
              var ip = data[info_hash][peer].ip;
              result += ip.length + ":" + ip;
            result += "4:port";
              var port = data[info_hash][peer].port;
              result += "i" + port + "e";
          }
        result += "e";
      }
    }
  result += "e";
  return result;
}

function encodeResponse(info_hash) {
  var result = "";
  result += "d";
    result += "8:interval";
      result += "i" + interval + "e";
    result += "5:peers";
    result += encodePeerList(info_hash);
  result += "e";
  return result;
}

// add param address for tor addresse
const server = http.createServer((req, res) => {
  var requestUrl = url.parse(req.url);
  if(requestUrl.pathname === "/announce") {
    var params = parseParameters(requestUrl.query);
    if(params.hasOwnProperty("info_hash")
      && params.hasOwnProperty("peer_id")
      && params.hasOwnProperty("uploaded")
      && params.hasOwnProperty("downloaded")
      && params.hasOwnProperty("left"))
    {
      console.log("request from " + req.connection.remoteAddress);
      if(params.hasOwnProperty("event")) {
        console.log("event: " + params.event)
      } else {
        console.log("no event");
      }
      if(params.hasOwnProperty("address")) {
        // tor case
        addTorEntry(params.info_hash, params.peer_id, params.address);
      } else {
        // regular case
        var ip;
        if(params.hasOwnProperty("ip")) {
          ip = params.ip;
        } else {
          ip = req.connection.remoteAddress;
        }
        addEntry(params.info_hash, params.peer_id, ip, params.port);
      }
      var responseText = encodeResponse(params.info_hash);
      console.log(responseText);
      res.statusCode = 200;
      res.end(responseText);
      return;
    }
  }
  res.statusCode = 400;
  res.end("invalid request\n")
});

server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
