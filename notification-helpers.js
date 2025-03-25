/**
 * Utility functions for handling notifications
 */

/**
 * Determines if a notification is an admin response
 * @param {Object} notification - The notification object
 * @returns {boolean} - True if the notification is an admin response
 */
export function isAdminResponse(notification) {
  return (
    notification.type === "concern" ||
    notification.type === "new_concern" ||
    notification.isAdminResponse === true ||
    (notification.subject && notification.subject.toLowerCase().includes("concern"))
  )
}

/**
 * Determines if a notification is an event notification
 * @param {Object} notification - The notification object
 * @returns {boolean} - True if the notification is an event notification
 */
export function isEventNotification(notification) {
  return (
    notification.eventName ||
    notification.eventDate ||
    notification.amenity ||
    notification.type === "payment_required" ||
    notification.type === "payment_confirmed" ||
    notification.type === "event_confirmed"
  )
}

/**
 * Determines if an event requires payment
 * @param {Object} notification - The notification object
 * @param {string} eventName - The event name
 * @returns {boolean} - True if the event requires payment
 */
export function requiresPayment(notification, eventName) {
  // If explicitly marked as payment confirmed or paid, no payment is required
  if (
    notification.type === "payment_confirmed" ||
    notification.paymentStatus === "paid" ||
    notification.isPaid === true
  ) {
    return false
  }

  // If explicitly marked as requiring payment, payment is required
  if (notification.type === "payment_required") {
    // Check for free event types
    const freeEventTypes = ["birthday", "meeting", "community"]
    if (notification.eventType && freeEventTypes.some((type) => notification.eventType.toLowerCase().includes(type))) {
      return false
    }

    // Check event name for keywords that suggest it's a free event
    const birthdayKeywords = ["birthday", "bday", "celebration", "anniversary"]
    const eventNameLower = (eventName || "").toLowerCase()
    if (birthdayKeywords.some((keyword) => eventNameLower.includes(keyword))) {
      return false
    }

    return true
  }

  // If message mentions payment but no other indicators suggest it's been paid
  if (notification.message && notification.message.includes("proceed with the payment")) {
    return true
  }

  return false
}

/**
 * Gets the appropriate status text for an event notification
 * @param {Object} notification - The notification object
 * @param {string} eventName - The event name
 * @returns {string} - The status text
 */
export function getEventStatus(notification, eventName) {
  if (notification.type === "event_cancelled" || notification.type === "event_deleted") {
    return "Cancelled"
  }

  if (
    notification.type === "payment_confirmed" ||
    notification.paymentStatus === "paid" ||
    notification.isPaid === true
  ) {
    return "Payment Confirmed"
  }

  if (requiresPayment(notification, eventName)) {
    return "Payment Required"
  }

  return "Confirmed"
}

