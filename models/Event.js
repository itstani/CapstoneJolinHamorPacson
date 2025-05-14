const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
    eventName: {
        type: String,
        required: true
    },
    HomeownerName: {
        type: String,
        required: true
    },
    eventDate: {
        type: String,
        required: true
    },
    startTime: {
        type: String,
        required: true
    },
    endTime: {
        type: String,
        required: true
    },
    amenity: {
        type: String,
        required: true
    },
    eventType: {
        type: String
    },
    guests: {
        number: {
            type: Number,
            required: true
        },
        names: [{
            type: String
        }]
    },
    homeownerStatus: {
        type: String,
        required: true
    },
    userEmail: {
        type: String,
        required: true
    },
    isPaid: {
        type: Boolean,
        default: false
    },
    isApproved: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Event', eventSchema); 