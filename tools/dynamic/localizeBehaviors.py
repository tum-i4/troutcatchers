#!/usr/bin/python

from trout.utils.db import *
from trout.conf.config import *
from trout.utils.graphics import *
from trout.learning.feature_extraction import *
from trout.learning.scikit_learners import *
from trout.learning.hmm_learner import *
import pickledb
import argparse, os, glob, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="localizeBehaviors.py", description="Uses the dynamic, HMM-based approach to classify and localize malicious behaviors")
    parser.add_argument("-x", "--malwaredir", help="The directory containing the malicious traces", required=True)
    parser.add_argument("-g", "--goodwaredir", help="The directory containing the benign traces", required=True)
    parser.add_argument("-f", "--fileextension", help="The extension of the trace files", required=False, default="log")
    parser.add_argument("-i" , "--includeargs", help="Whether to include arguments in the parsed traces", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-c", "--localization", help="The method used to localize malicious behaviors", required=False, default="binary", choices=["binary", "window", "n-ary"])
    parser.add_argument("-w", "--windowsize", help="The size of the window to consider with the \"window\" localization method", required=False, default=3, type=int)
    parser.add_argument("-s", "--splitsize", help="The value of (n) upon considering the \"n-ary\" split localization method", required=False, default=3, type=int)
    parser.add_argument("-t", "--tau", help="The threshold log likelihood value to consider for HMM classification", required=False, type=float, default=0.0)
    parser.add_argument("-l", "--lambd", help="The maximum length to consider per trace", required=False, type=int, default=0)
    parser.add_argument("-o", "--storeresults", help="Whether to store results in the database", required=False, default="no", choices=["yes", "no"])
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Bonjour Monsieur.")

        #db = DB()
        # 1. Retrieve the traces
        malwareLogs = glob.glob("%s/*.%s" % (arguments.malwaredir, arguments.fileextension)
        goodwareLogs = glob.glob("%s/.%s" % (arguments.goodwaredir, arguments.fileextension)
        if len(malwareTraces) < 1 or len(goodwareTraces) < 1:
            prettyPrint("Could not retrieve traces. Retrieved: %s malware traces and %s goodware traces" % (len(malwareLogs), len(goodwareLogs), "error")
            return False

        prettyPrint("Successfully retrieved %s malware traces and %s goodware traces" % (len(malwareLogs), len(goodwareLogs))

        # 2. Parsing log traces to retrieve sequences and dynamic features
        prettyPrint("Parsing logs")
        malwareTraces, goodwareTraces = [], []
        hashesDB = pickledb.load(HASHES_DB, False)
        for log in malwareLogs+goodwareLogs:
            appHash = log[log.rfind('/')+1:log.rfind("_filtered")].lower()
            appName = hashesDB.get(appHash)
            appName = appName if appName else appHash
            trace, features = extractDroidmonFeatures(log)
            if log in malwareLogs:
                malwareTraces.append(log)
            else:
                goodwareTraces.append(log)

        # 3. Split data into training and test 
        trainingTraces = []
        twoThirds = len(goodwareTraces) * 0.67
        while len(trainingTraces) < twoThirds:
            trainingTraces.append(goodwareTraces.pop(random.randint(0, len(goodwareTraces)-1))
            
        # 4. Train a HMM
        # 4.1. Retrieve all possible observations
        allObservations = []
        for item in trainingTraces+goodwareTraces+malwareTraces:
            for obs in item[1]:
                if not obs in allObservations:
                    allObservations.append(obs)

        prettyPrint("Successfully retrieved %s observations from all traces" % len(allObservations))
        # 4.2. Construct and train Hidden Markov model
        Pi = [1.0, 0.0] # Always start from a benign state
        A = [[0.5, 0.5], [0.5, 0.5]]
        B = numpy.random.random((2, len(allObservations))).tolist()
        prettyPrint("Building the hidden Markov model")
        hmm = HiddenMarkovModel(A, B, Pi, allObservations)
        prettyPrint("Training the model")
        
        hmm.trainModel([trace[1] for trace in trainingTraces])
        # 4.3. Perform the classification
        allTaus = [arguments.tau] if arguments.tau != 0.0 else [-50, -100, -250, -500, -1000]
        allLambdas = [arguments.lambd] if arguments.lambd != 0 else [10, 25, 50, 100, 250, 500, 1000]
        groundTruth = [0]*len(goodwareTraces) + [1]*len(malwareTraces)
        metrics = {}
        for tau in allTaus:
            for lambd in allLambdas:
                prettyPrint("Classifying using a tau of %s and lambda of %s" % (tau, lambd))
                predicted = []
                for trace in goodwareTraces+malwareTraces:
                    prettyPrint("Classifying \"%s\"" % trace[0])
                    # Preparing the trace for classification
                    new_trace = trace[1][:lambd] if len(trace[1]) > lambd else trace
                    sequence = ghmm.EmissionSequence(hmm.sigma, new_trace)
                    # Calculating the log likelihood for that trace
                    logLikelihood = hmm.ghmmModel.loglikelihood(x_new)
                    prettyPrint("log P(O|lambda)=%s" % logLikelihood, "debug")
                    # Classifying the trace
                    prettyPrint("Classifying with a threshold of %s" % hmmThreshold)
                    if logLikelihood < tau:
                        # The sequence is suspicious
                        predicted.append(1)
                    else:
                        predicted.append(0)

                # 4.4. Calculate metrics for current tau and lambda
                tmp = calculateMetrics(groundTruth, predicted)
                metrics["tau%s_lambda%s" % (tau, lambd)] = (tmp, hmm)
                
        # 5. Decide upon the best metrics
        bestFScore, bestHMM = 0.0, None
        for metric in metrics:
           # TODO: Carry on 

        
        # 5. Close the database
        #db.close()

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
