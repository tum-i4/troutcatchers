#!/usr/bin/python

from trout.utils.db import *
from trout.conf.config import *
from trout.learning.feature_extraction import *
import pickledb
import argparse, os, glob, json

def defineArguments():
    parser = argparse.ArgumentParser(prog="extractFeatures.py", description="Extracts features from statically generated app representations")
    parser.add_argument("-i", "--indir", help="The input directory containing the apps' representations", required=True)
    parser.add_argument("-a", "--apptype", help="The type of apps contained within the input directory", required=False, default="goodware", choices=["goodware", "malware"])
    parser.add_argument("-t", "--featuretype", help="The type of features to extract from the data", required=False, default="general", choices=["general"]) #TODO: to extend
    parser.add_argument("-o", "--outfile", help="The file to dump the extracted features to (i.e., .csv or .tsv)", required=False, default="out.csv")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Good day to you, Sire.")

        # 1. Load all representations from input file
        allfiles = glob.glob("%s/*.json" % arguments.indir)
        if len(allfiles) < 1:
            prettyPrint("Could not find any input files under \"%s\". Exiting" % arguments.infile, "error")
            return False

        # 2. Store data about the apps in the database
        hashesDB = pickledb.load(HASHES_DB, False)
        troutDB = DB()
        outfile = open(arguments.outfile, "w")  
        attrsWritten = False
        delimiter = '\t' if arguments.outfile.lower().find(".tsv") != -1 else ','
        for f in allfiles:
            content = json.loads(open(f).read())
            if len(content) < 1:
               prettyPrint("Could not find data for app \"%s\". Skipping" % f, "warning")
               continue 
            
            # 2.a. Gather and store information about the app
            appHash = f[f.rfind("/")+1:].replace(".json","").lower()
            appName = hashesDB.get(appHash) if hashesDB.get(appHash) else "Unknown"
            troutDB.insert("apps", ["appID", "appRepr", "appType", "appName", "appReprPath"], [appHash, "static", arguments.apptype, appName, f])

            # 2.b. Extract features
            attributes, features = extractStaticFeatures(content)
            attributes = str(attributes).replace("'", "").replace(' ','')
            features = str(features).replace(' ', '')
            troutDB.insert("featurevectors", ["fvApp", "fvType", "fvLegend", "fvVector"], [appHash, "static_%s" % arguments.featuretype, attributes, features]) 
 
            # 2.c.. Store extracted vectors to output file
            if not attrsWritten:
                outfile.write("hash%spackage_name%s%s%slabel\n" % (delimiter, delimiter, attributes[1:-1].replace(',', delimiter), delimiter))
                attrsWritten = True
            label = 0 if arguments.apptype == "goodware" else 1
            outfile.write("%s%s%s%s%s%s%s\n" % (appHash, delimiter, appName, delimiter, features[1:-1].replace(',', delimiter), delimiter, label))


        # 4. Close the database
        troutDB.close()
        outfile.close()

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
