#!/usr/bin/python

from trout.utils.db import *
from trout.conf.config import *
from trout.learning.feature_extraction import *
from trout.learning.scikit_learners import *
from trout.visualization.visualize_data import *
import pickledb
import argparse, os

def defineArguments():
    parser = argparse.ArgumentParser(prog="classifyApps.py", description="Classifies apps based on feature vectors retrieved from the database")
    parser.add_argument("-t", "--featurestype", help="The type of features to extract from the sequences.", required=True, choices=["counts"])
    parser.add_argument("-s", "--storeresults", help="Whether to store the classification results to the database", required=True, choices=["yes", "no"])
    parser.add_argument("-a", "--algorithm", help="The algorithm(s) to use for classification", required=False, default="ensemble", choices=["knn", "forest", "svm", "ensemble"])
    parser.add_argument("-f", "--selectkbest", help="The number of best features to select from the feature vectors", required=False, default=0)
    parser.add_argument("-k", "--kfold", help="The number of folds to use in cross-validation", required=False, default="2")
    parser.add_argument("-v", "--visualize", help="Whether to generate visualizations of the feature vectors and the classification accuracies", required=False, choices=["yes", "no"])
    parser.add_argument("-d", "--dimensionality", help="The dimensionality adopted by the visualization algorithms", required=False, choices=["2", "3"], default=2)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Buongiorno signore.")

        db = DB()
        # 1. Retrieve the feature vectors from the database
        prettyPrint("Retrieving feature vectors from the database")
        query = "SELECT fvType,fvLegend,fvVector,appName,appDesc FROM featureVectors,apps WHERE fvApp=appID"
        allApps = db.execute(query)
        if allApps == None:
            prettyPrint("Unable to retrieve any feature vectors from the database. Exiting", "error")
            return False

        allVectors = allApps.fetchall()
        prettyPrint("Successfully retrieved %s feature vectors from the database" % len(allVectors))
        # 2. Segregate benign and malicious feature vectors
        X, y = [], []
        for v in allVectors: 
            X.append(eval(v[2]))
            if v[4] == "malware":
                y.append(1)
            elif v[4] == "goodware":
                y.append(0)

        if len(X) < 1:
            prettyPrint("Could not retrieved any feature vectors for classification")
            return False
 
        prettyPrint("Successfully retrieved %s vectors" % (len(X)))

        # 3. Do the classification
        # 3.a. Retrieve the list of classifiers
        allClassifiers = [i[1] for i in db.select([], "learners", []).fetchall()]
        K = [k for k in allClassifiers if k.lower().find("knn") != -1]
        E = [e for e in allClassifiers if e.lower().find("trees") != -1]
        S = [s for s in allClassifiers if s.lower().find("svm") != -1]
        if len(allClassifiers) < 1:
            prettyPrint("Unable to retrieve any learning algorithms from the database. Exiting")
            return False

        if arguments.algorithm == "knn" or arguments.algorithm == "ensemble":
            for k in K:
                prettyPrint("Predicting using %s" % k)
                predicted = predictKFoldKNN(X, y, K=int(k.split('-')[-1]), selectKBest=int(arguments.selectkbest), kfold=int(arguments.kfold))
                metrics = calculateMetrics(predicted, y)
                prettyPrint("Metrics for %s: %s" % (k, str(metrics)))
                if arguments.storeresults == "yes":
                    # Save results into the database
                    db.insert("results", ["rLearner","rTimestamp","rAccuracy","rRecall","rSpecificity","rPrecision","rFscore"], [allClassifiers.index(k), getTimestamp(), metrics["accuracy"], metrics["recall"], metrics["specificity"], metrics["precision"], metrics["f1score"]])

        if arguments.algorithm == "forest" or arguments.algorithm == "ensemble":
            for rf in E:
                prettyPrint("Predicting using %s" % rf)
                predicted = predictKFoldRandomForest(X, y, estimators=int(rf.split('-')[-1]), selectKBest=int(arguments.selectkbest), kfold=int(arguments.kfold))
                metrics = calculateMetrics(predicted, y)
                prettyPrint("Metrics for %s: %s" % (rf, str(metrics)))
                if arguments.storeresults == "yes":
                    # Save results into the database
                    db.insert("results", ["rLearner","rTimestamp","rAccuracy","rRecall","rSpecificity","rPrecision","rFscore"], [allClassifiers.index(rf), getTimestamp(), metrics["accuracy"], metrics["recall"], metrics["specificity"], metrics["precision"], metrics["f1score"]])

        if arguments.algorithm == "svm" or arguments.algorithm == "ensemble":
            for s in S:
                prettyPrint("Predicting using %s" % s)
                predicted = predictKFoldSVM(X, y, selectKBest=int(arguments.selectkbest), kfold=int(arguments.kfold))
                metrics = calculateMetrics(predicted, y)
                prettyPrint("Metrics for %s: %s" % (k, str(metrics)))
                if arguments.storeresults == "yes":
                    # Save results into the database
                    db.insert("results", ["rLearner","rTimestamp","rAccuracy","rRecall","rSpecificity","rPrecision","rFscore"], [allClassifiers.index(s), getTimestamp(), metrics["accuracy"], metrics["recall"], metrics["specificity"], metrics["precision"], metrics["f1score"]])

        if arguments.algorithm == "ensemble":
            prettyPrint("Predicting using ensemble of classifiers")
            predicted = predictKFoldEnsemble(X, y, classifiers=K+E+S, kfold=int(arguments.kfold), selectKBest=int(arguments.selectkbest))
            metrics = calculateMetrics(predicted, y)
            prettyPrint("Metrics for %s: %s" % (k, str(metrics)))
            if arguments.storeresults == "yes":
                # Save results into the database
                db.insert("results", ["rLearner","rTimestamp","rAccuracy","rRecall","rSpecificity","rPrecision","rFscore"], [allClassifiers.index("Ensemble"), getTimestamp(), metrics["accuracy"], metrics["recall"], metrics["specificity"], metrics["precision"], metrics["f1score"]])

        # 4. Visualize data
        if arguments.visualize == "yes":
            d = int(arguments.dimensionality)
            prettyPrint("Visualizing results in %s-d" % arguments.dimensionality)
            # 4.a. The original data
            prettyPrint("Visualizing original data with %s features" % arguments.featurestype)
            reduceAndVisualize(X, y, dim=d, figTitle="Original with %s features" % arguments.featurestype, appNames=[v[3] for v in allVectors])
            # 4.b. The ensemble data (TODO: Visualize all algorithms?)
            prettyPrint("Visualizing classified data with ensemble")
            reduceAndVisualize(X, predicted, dim=d, fitTitle="Ensemble with %s features" % arguments.featurestype, appNames=[v[3] for v in allVectors])

        # 5. Close the database
        db.close()

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
