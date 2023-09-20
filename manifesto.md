# Bloogle 
This project is a SMALL scale search engine that do not support shrading in any way without massive changes !!! 

## tools dbs and langs 
main langs : go and py and bash for scripts
dbs : redis for caches and neo4j 
go libs : 
py libs : 

## the desing : 

## The content focused based search engine will add ArticleRank algorithm 
I want to rank sites for the quality based on minimal number of good blogs and sites - thier might be a lot of links to unterlated sites like google or repos in github etc ... 
that do not have inpormative info for us. 
then it will not automatically add links in the site to our db - it will rank the site after crawl and rank it fro 0-1 
for how good it is . 
## The SiteRank algorithm 
I want to filter unrelated sites - it will be based on the AritcleRank . 


## PageRank 
the pagerank will be based on google's formula + SiteRank algorithm in it . 
in addation to that the base site will have boost to their rank . 


## How regular site can become base site ? 
if the site have high SiteRank and realy good PageRank it can become basesite and have the privilges of base site . 


## Crawler 
the crawler it written in GO lang and uses redis queue . 
it fetches all the links form a site , sending the pages to the RANKING queue (using Burrows-Wheeler Transform on the content of the the pages and localy saves the temprarly). 
and keep going and fetching more sites . 
the crawler and the Ranker are synced to avoid bottleneck issues. 
 
