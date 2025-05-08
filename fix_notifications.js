require('dotenv').config();
const { MongoClient, ObjectId } = require('mongodb');

const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME || 'avidadb';

async function fixPaymentRequiredNotifications() {
  const client = new MongoClient(uri, { useUnifiedTopology: true });
  try {
    await client.connect();
    const db = client.db(dbName);
    const notifications = db.collection('notifications');
    const aevents = db.collection('aevents');

    // Find all payment_required notifications with a relatedId
    const notifs = await notifications.find({ type: 'payment_required', relatedId: { $exists: true } }).toArray();
    let fixed = 0;

    for (const notif of notifs) {
      let event;
      // Try to find the event by relatedId
      try {
        event = await aevents.findOne({ _id: new ObjectId(notif.relatedId) });
      } catch (e) {
        // relatedId might not be a valid ObjectId
        event = null;
      }

      if (!event && notif.eventName && notif.eventDate) {
        // Try to find by eventName and eventDate
        event = await aevents.findOne({ eventName: notif.eventName, eventDate: notif.eventDate });
      }

      if (event && notif.relatedId !== event._id.toString()) {
        // Update the notification's relatedId to the correct event _id
        await notifications.updateOne(
          { _id: notif._id },
          { $set: { relatedId: event._id.toString() } }
        );
        console.log(`Fixed notification ${notif._id}: set relatedId to ${event._id}`);
        fixed++;
      }
    }

    console.log(`Done! Fixed ${fixed} notifications.`);
  } catch (err) {
    console.error('Error fixing notifications:', err);
  } finally {
    await client.close();
  }
}

fixPaymentRequiredNotifications();