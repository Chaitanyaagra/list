/*
  SHARED FIREBASE CONFIG
  This is safe to be public; security is enforced by Authentication + Firestore Rules,
  not by hiding this file. Baking it in here means the app always has a working config,
  even if a device has trouble saving the "Connect" step's local copy.
*/
window.PM_FIREBASE_CONFIG = window.PM_FIREBASE_CONFIG || {
  apiKey: "AIzaSyAfu0-Ih3nFtimeL63_DTPcBZ6MdJxp22I",
  authDomain: "list-1a1d0.firebaseapp.com",
  projectId: "list-1a1d0",
  storageBucket: "list-1a1d0.firebasestorage.app",
  messagingSenderId: "136541430311",
  appId: "1:136541430311:web:d9856b2da1b1e9d246a402"
};
