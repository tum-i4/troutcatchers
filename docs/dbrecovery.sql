/*
Stores different representations of apps
appID: The hash of the app's APK archive
appRepr: The type of data representing the app (e.g., API call trace)
appType: The type of the app (i.e., malicious or benign)
appName: The packaged name of an app
appReprPath: The path to the file storing the app's representation
*/
CREATE TABLE apps(
    appID		    TEXT,
    appRepr		    TEXT,
    appType		    TEXT,
    appName		    TEXT,
    appReprPath		    TEXT,
    PRIMARY KEY (appID, appRepr)
);

/*
Stores pre-defined malicious behaviors to be injected into benign API call traces
bID: ID
bDesc: A description of the behavior (e.g., which malware family it represents)
bSequence: A sequence of API calls representing the behavior
bTimestamp: A timestamp of when the behavior has been inserted
*/
CREATE TABLE behaviors(
    bID			    INTEGER PRIMARY KEY AUTOINCREMENT,
    bDesc		    TEXT,
    bSequence		    TEXT,
    bTimestamp		    TEXT
);

/*
Store results of various experiments
dpID: ID
dpRun: The ID of the run during which the scores were recorded
dpLearner: The ID of the learner used to generate that point
dpInsertP: The probability of inserting malicious behaviors in sequences (if applicable, otherwise 0.0)
dpAccuracy: Classification accuracy
dpRecall: Recall (TP/P)
dpSpecificity: Specificity (TN/N)
dpPrecision: Precision (TP/TP+FP)
dpFscore: F1 Score (2*(1/precision+1/recall))
*/
CREATE TABLE datapoint( 
    dpID	       	    INTEGER PRIMARY KEY AUTOINCREMENT, 
    dpRun		    INTEGER,
    dpLearner		    INTEGER,
    dpInsertP	 	    REAL,
    dpAccuracy		    REAL,
    dpRecall		    REAL,
    dpSpecificity	    REAL,
    dpPrecision	 	    REAL,
    dpFscore		    REAL,
    FOREIGN KEY (dpLearner) REFERENCES parent(learnerID),
    FOREIGN KEY (dpRun) REFERENCES parent(runID)
);

/*
Stores vectors of numerical/categorical features extracted from app representations
fvID: ID
fvApp: The app represented by the feature vector
fvType: A textual description of the vector's features (e.g., counts, TF-IDF, text, etc.)
fvLegend: A vector describing the features in the feature vector
fvVector: The feature vector itself
*/
CREATE TABLE featurevectors(
    fvID		    INTEGER PRIMARY KEY AUTOINCREMENT,
    fvApp		    TEXT,
    fvType		    TEXT,
    fvLegend		    TEXT,
    fvVector		    TEXT,
    FOREIGN KEY (fvApp) REFERENCES parent(appID)
);

/*
Stores information about the machine learners used during experiments
learnerID: ID
learnerName: A unique/identifiable name of the learner
*/
CREATE TABLE learners(
    learnerID  		    INTEGER PRIMARY KEY AUTOINCREMENT, 
    learnerName    	    TEXT
);

/*
Stores information about one run of an experiment
runID: ID
runDesc: A textual description of the run
runStaTimestamp: The starting time of the run
runEndTimestamp: The ending time of the run
*/
CREATE TABLE run( 
    runID       	    INTEGER,
    runDesc		    TEXT,
    runStaTimestamp	    TEXT,
    runEndTimestamp	    TEXT
    PRIMARY KEY (runID)
);

INSERT INTO learners (learnerName) VALUES ("KNN-10");
INSERT INTO learners (learnerName) VALUES ("KNN-25");
INSERT INTO learners (learnerName) VALUES ("KNN-50");
INSERT INTO learners (learnerName) VALUES ("KNN-100");
INSERT INTO learners (learnerName) VALUES ("KNN-250");
INSERT INTO learners (learnerName) VALUES ("KNN-500");
INSERT INTO learners (learnerName) VALUES ("Trees-10");
INSERT INTO learners (learnerName) VALUES ("Trees-25");
INSERT INTO learners (learnerName) VALUES ("Trees-50");
INSERT INTO learners (learnerName) VALUES ("Trees-100");
INSERT INTO learners (learnerName) VALUES ("SVM");
INSERT INTO learners (learnerName) VALUES ("Ensemble");
/*INSERT INTO learners (learnerName) VALUES ("HMM-250-50")*/
